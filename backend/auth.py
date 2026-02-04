"""
Authentication Module
JWT-based authentication with role-based access control
"""

import os
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional, Dict
import hashlib
import jwt
from flask import request, jsonify
import logging

logger = logging.getLogger(__name__)

# Configuration
SECRET_KEY = os.getenv('JWT_SECRET', 'your-secret-key-change-in-production')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv('JWT_EXPIRATION_MINUTES', 1440))  # 24 hours


def hash_password(password: str) -> str:
    """Hash password using SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password"""
    return hash_password(plain_password) == hashed_password


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_token(token: str) -> Optional[Dict]:
    """Decode and validate JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning(f"Token expired")
        return None
    except jwt.InvalidTokenError:
        logger.warning(f"Invalid token")
        return None


def get_token_from_request() -> Optional[str]:
    """Extract token from request headers"""
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return None
    
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return None
    
    return parts[1]


def token_required(f):
    """Decorator for protecting endpoints with token authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_from_request()
        
        if not token:
            return jsonify({'error': 'Token missing'}), 401
        
        payload = decode_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        return f(payload, *args, **kwargs)
    
    return decorated


def role_required(required_role: str):
    """Decorator for role-based access control"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = get_token_from_request()
            
            if not token:
                return jsonify({'error': 'Token missing'}), 401
            
            payload = decode_token(token)
            if not payload:
                return jsonify({'error': 'Invalid or expired token'}), 401
            
            user_role = payload.get('role', 'viewer')
            
            # Role hierarchy: admin > tester > viewer
            role_hierarchy = {'admin': 3, 'tester': 2, 'viewer': 1}
            required_level = role_hierarchy.get(required_role, 0)
            user_level = role_hierarchy.get(user_role, 0)
            
            if user_level < required_level:
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            return f(payload, *args, **kwargs)
        
        return decorated
    return decorator


class AuthManager:
    """Authentication management"""
    
    def __init__(self, db_session):
        self.db = db_session
    
    def register_user(self, username: str, email: str, password: str, role: str = 'viewer') -> Dict:
        """Register new user"""
        from database import User
        
        # Check if user exists
        existing = self.db.query(User).filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing:
            return {'success': False, 'error': 'User already exists'}
        
        # Create user
        password_hash = hash_password(password)
        user = User(
            username=username,
            email=email,
            password_hash=password_hash,
            role=role
        )
        
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        
        logger.info(f"User registered: {username}")
        return {'success': True, 'user_id': user.id, 'username': username}
    
    def login_user(self, username: str, password: str) -> Dict:
        """Authenticate user and return token"""
        from database import User
        
        user = self.db.query(User).filter(User.username == username).first()
        
        if not user or not verify_password(password, user.password_hash):
            logger.warning(f"Login failed for user: {username}")
            return {'success': False, 'error': 'Invalid credentials'}
        
        if not user.active:
            return {'success': False, 'error': 'User account is inactive'}
        
        # Update last login
        user.last_login = datetime.utcnow()
        self.db.commit()
        
        # Create token
        token = create_access_token({
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role
        })
        
        logger.info(f"User logged in: {username}")
        return {
            'success': True,
            'token': token,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role
            }
        }
    
    def get_user(self, user_id: int) -> Optional[Dict]:
        """Get user by ID"""
        from database import User
        
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user:
            return None
        
        return {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'created_at': user.created_at.isoformat()
        }
    
    def change_password(self, user_id: int, old_password: str, new_password: str) -> Dict:
        """Change user password"""
        from database import User
        
        user = self.db.query(User).filter(User.id == user_id).first()
        
        if not user:
            return {'success': False, 'error': 'User not found'}
        
        if not verify_password(old_password, user.password_hash):
            return {'success': False, 'error': 'Old password is incorrect'}
        
        user.password_hash = hash_password(new_password)
        self.db.commit()
        
        logger.info(f"Password changed for user: {user.username}")
        return {'success': True, 'message': 'Password changed successfully'}

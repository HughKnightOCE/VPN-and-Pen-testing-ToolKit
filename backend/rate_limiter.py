"""
Rate Limiting Module
In-memory token bucket algorithm for API rate limiting
"""

import time
from collections import defaultdict
from threading import Lock
import logging

logger = logging.getLogger(__name__)


class RateLimiter:
    """Token bucket rate limiter"""
    
    def __init__(self, requests_per_minute: int = 60):
        self.requests_per_minute = requests_per_minute
        self.requests_per_second = requests_per_minute / 60.0
        
        # Token bucket per IP/user
        self.buckets = defaultdict(lambda: {
            'tokens': self.requests_per_second,
            'last_update': time.time()
        })
        self.lock = Lock()
        self.blocked_ips = set()
    
    def is_allowed(self, identifier: str) -> bool:
        """Check if request is allowed for identifier (IP or user_id)"""
        
        # Check if blocked
        if identifier in self.blocked_ips:
            return False
        
        with self.lock:
            now = time.time()
            bucket = self.buckets[identifier]
            
            # Add tokens based on time elapsed
            time_passed = now - bucket['last_update']
            bucket['tokens'] = min(
                self.requests_per_second,
                bucket['tokens'] + time_passed * self.requests_per_second
            )
            bucket['last_update'] = now
            
            # Check if we have tokens
            if bucket['tokens'] >= 1:
                bucket['tokens'] -= 1
                return True
            
            return False
    
    def block_identifier(self, identifier: str):
        """Block an identifier (IP or user)"""
        with self.lock:
            self.blocked_ips.add(identifier)
            logger.warning(f"Blocked identifier due to rate limit: {identifier}")
    
    def unblock_identifier(self, identifier: str):
        """Unblock an identifier"""
        with self.lock:
            self.blocked_ips.discard(identifier)
            logger.info(f"Unblocked identifier: {identifier}")
    
    def get_status(self, identifier: str) -> dict:
        """Get rate limit status for identifier"""
        with self.lock:
            bucket = self.buckets.get(identifier, {})
            tokens = bucket.get('tokens', 0)
            
            return {
                'tokens_remaining': int(tokens),
                'max_tokens': self.requests_per_second,
                'requests_per_minute': self.requests_per_minute,
                'blocked': identifier in self.blocked_ips
            }


class RateLimitMiddleware:
    """Flask middleware for rate limiting"""
    
    def __init__(self, app, requests_per_minute: int = 60):
        self.app = app
        self.limiter = RateLimiter(requests_per_minute)
        self.excluded_paths = ['/api/auth/login', '/api/auth/register', '/api/health']
    
    def get_identifier(self):
        """Get identifier from request (IP address or user ID from token)"""
        from flask import request
        from auth import get_token_from_request, decode_token
        
        # Try to get from token first
        token = get_token_from_request()
        if token:
            payload = decode_token(token)
            if payload:
                return f"user_{payload.get('user_id', 'unknown')}"
        
        # Fall back to IP address
        return request.remote_addr or 'unknown'
    
    def should_limit(self, path: str) -> bool:
        """Check if path should be rate limited"""
        return path not in self.excluded_paths
    
    def check_rate_limit(self):
        """Check rate limit and return response if exceeded"""
        from flask import request, jsonify
        
        if not self.should_limit(request.path):
            return None
        
        identifier = self.get_identifier()
        
        if not self.limiter.is_allowed(identifier):
            status = self.limiter.get_status(identifier)
            logger.warning(f"Rate limit exceeded for {identifier}")
            return jsonify({
                'error': 'Rate limit exceeded',
                'retry_after': 60
            }), 429
        
        return None


# Global rate limiter instance
rate_limiter = RateLimiter(requests_per_minute=60)

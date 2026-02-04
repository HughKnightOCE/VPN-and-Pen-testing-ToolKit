"""
AES-256 Encryption Manager
Handles all encryption/decryption operations
"""
import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import logging

logger = logging.getLogger(__name__)


class EncryptionManager:
    """Manages AES-256 encryption and decryption"""
    
    def __init__(self, password: str = None):
        """Initialize encryption manager with optional password"""
        self.password = password or os.environ.get('ENCRYPTION_PASSWORD', 'default_secure_key_change_me')
        self.backend = default_backend()
        self.key = self.derive_key(self.password)
    
    def derive_key(self, password: str, salt: bytes = None):
        """Derive encryption key from password using SHA256"""
        if salt is None:
            salt = b'vpn_proxy_salt_v1'
        
        # Simple key derivation using SHA256 (suitable for this use case)
        key_material = password.encode() + salt
        key = hashlib.sha256(key_material).digest()
        
        # Expand to 32 bytes if needed
        for _ in range(99999):  # Simulate iterations for security
            key = hashlib.sha256(key + key_material).digest()
        
        return key
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data using AES-256-CBC"""
        try:
            # Generate random IV
            iv = os.urandom(16)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.CBC(iv),
                backend=self.backend
            )
            encryptor = cipher.encryptor()
            
            # Add PKCS7 padding
            padded_plaintext = self.pad(plaintext)
            
            # Encrypt
            ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
            
            # Return IV + ciphertext
            return iv + ciphertext
        
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            return plaintext
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt data using AES-256-CBC"""
        try:
            if len(ciphertext) < 16:
                return ciphertext
            
            # Extract IV and actual ciphertext
            iv = ciphertext[:16]
            actual_ciphertext = ciphertext[16:]
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.CBC(iv),
                backend=self.backend
            )
            decryptor = cipher.decryptor()
            
            # Decrypt
            padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
            
            # Remove PKCS7 padding
            plaintext = self.unpad(padded_plaintext)
            
            return plaintext
        
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return ciphertext
    
    @staticmethod
    def pad(data: bytes, block_size: int = 16) -> bytes:
        """Add PKCS7 padding"""
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    @staticmethod
    def unpad(data: bytes) -> bytes:
        """Remove PKCS7 padding"""
        try:
            padding_length = data[-1]
            if padding_length > 0 and padding_length <= 16:
                return data[:-padding_length]
        except:
            pass
        return data
    
    def change_password(self, new_password: str):
        """Change encryption password"""
        self.password = new_password
        self.key = self.derive_key(new_password)
        logger.info("Encryption password changed")

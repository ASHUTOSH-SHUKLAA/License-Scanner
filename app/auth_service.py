"""
Authentication service for the License Compliance Scanner.

This module provides authentication functionality including password hashing,
JWT token generation/verification, and password complexity validation.

Requirements: 1.1, 1.2, 1.3, 1.4, 1.5
"""

from datetime import datetime, timedelta
from typing import Optional
import re
import jwt
from passlib.context import CryptContext
from config import get_settings


# Password hashing configuration using bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Get JWT configuration from settings
settings = get_settings()
JWT_SECRET_KEY = settings.jwt_secret_key
JWT_ALGORITHM = settings.jwt_algorithm
JWT_EXPIRATION_HOURS = settings.jwt_expiration_hours


class AuthService:
    """
    Service class for handling authentication operations.
    
    Provides methods for password hashing, validation, and JWT token management.
    """
    
    def __init__(self, secret_key: Optional[str] = None, expiration_hours: int = JWT_EXPIRATION_HOURS):
        """
        Initialize the authentication service.
        
        Args:
            secret_key: Secret key for JWT signing (defaults to JWT_SECRET_KEY)
            expiration_hours: Token expiration time in hours (defaults to 24)
        """
        self.secret_key = secret_key or JWT_SECRET_KEY
        self.algorithm = JWT_ALGORITHM
        self.expiration_hours = expiration_hours
    
    def hash_password(self, password: str) -> str:
        """
        Hash a plain text password using bcrypt.
        
        Args:
            password: Plain text password to hash
            
        Returns:
            Hashed password string
            
        Requirements: 1.1, 8.3
        """
        return pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify a plain text password against a hashed password.
        
        Args:
            plain_password: Plain text password to verify
            hashed_password: Hashed password to compare against
            
        Returns:
            True if password matches, False otherwise
            
        Requirements: 1.2
        """
        return pwd_context.verify(plain_password, hashed_password)
    
    def validate_password_complexity(self, password: str) -> tuple[bool, Optional[str]]:
        """
        Validate password complexity requirements.
        
        Requirements:
        - Minimum 8 characters
        - Character diversity (must contain multiple character types)
        
        Args:
            password: Password to validate
            
        Returns:
            Tuple of (is_valid, error_message)
            
        Requirements: 1.5
        """
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        # Check for character diversity
        has_lowercase = bool(re.search(r'[a-z]', password))
        has_uppercase = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[^a-zA-Z0-9]', password))
        
        # Require at least 2 different character types for diversity
        diversity_count = sum([has_lowercase, has_uppercase, has_digit, has_special])
        
        if diversity_count < 2:
            return False, "Password must contain at least 2 different character types (lowercase, uppercase, digits, special characters)"
        
        return True, None
    
    def create_access_token(self, user_id: int) -> str:
        """
        Generate a JWT access token for a user.
        
        Args:
            user_id: User ID to encode in the token
            
        Returns:
            JWT token string
            
        Requirements: 1.2
        """
        expiration = datetime.utcnow() + timedelta(hours=self.expiration_hours)
        
        payload = {
            "user_id": user_id,
            "exp": expiration,
            "iat": datetime.utcnow()
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        return token
    
    def verify_token(self, token: str) -> Optional[int]:
        """
        Verify and decode a JWT token.
        
        Args:
            token: JWT token string to verify
            
        Returns:
            User ID if token is valid, None otherwise
            
        Requirements: 1.3, 1.4
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            user_id = payload.get("user_id")
            
            if user_id is None:
                return None
                
            return user_id
            
        except jwt.ExpiredSignatureError:
            # Token has expired
            return None
        except jwt.InvalidTokenError:
            # Token is invalid (malformed, wrong signature, etc.)
            return None
        except Exception:
            # Any other error
            return None

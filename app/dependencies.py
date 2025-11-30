"""
FastAPI dependencies for the License Compliance Scanner.

This module provides reusable dependencies for authentication and authorization.

Requirements: 1.3, 1.4
"""

from typing import Annotated
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlmodel import Session

from app.auth_service import AuthService
from app.user_repository import UserRepository
from app.models import User
from app.database import get_session


# HTTP Bearer token security scheme
security = HTTPBearer()


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
    session: Session = Depends(get_session)
) -> User:
    """
    Dependency to get the current authenticated user from JWT token.
    
    Extracts and validates the JWT token from the Authorization header,
    then retrieves the corresponding user from the database.
    
    Args:
        credentials: HTTP Bearer credentials containing the JWT token
        session: Database session (injected)
        
    Returns:
        User: The authenticated user
        
    Raises:
        HTTPException 401: If token is invalid, expired, or user not found
        
    Requirements: 1.3, 1.4
    """
    auth_service = AuthService()
    
    # Extract token from credentials
    token = credentials.credentials
    
    # Verify and decode token
    user_id = auth_service.verify_token(token)
    
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": {
                    "code": "AUTHENTICATION_ERROR",
                    "message": "Invalid or expired token",
                    "details": {
                        "reason": "The provided token is invalid, expired, or malformed"
                    }
                }
            },
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    # Get user from database
    user_repo = UserRepository(session)
    user = user_repo.get_by_id(user_id)
    
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": {
                    "code": "AUTHENTICATION_ERROR",
                    "message": "User not found",
                    "details": {
                        "reason": "The user associated with this token no longer exists"
                    }
                }
            },
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    return user


# Type alias for dependency injection
CurrentUser = Annotated[User, Depends(get_current_user)]

"""
Authentication API routes for the License Compliance Scanner.

This module provides endpoints for user registration and login.

Requirements: 1.1, 1.2, 1.3, 1.4
"""

import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session

from app.api_models import RegisterRequest, LoginRequest, TokenResponse
from app.auth_service import AuthService
from app.user_repository import UserRepository, DuplicateUsernameError
from app.models import User
from app.database import get_session


router = APIRouter(prefix="/api/auth", tags=["authentication"])
logger = logging.getLogger(__name__)


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    response_description="JWT token for the newly created user",
    responses={
        201: {
            "description": "User successfully registered",
            "content": {
                "application/json": {
                    "example": {
                        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                        "token_type": "bearer"
                    }
                }
            }
        },
        400: {
            "description": "Validation error - username exists or password requirements not met",
            "content": {
                "application/json": {
                    "example": {
                        "error": {
                            "code": "VALIDATION_ERROR",
                            "message": "Password does not meet complexity requirements",
                            "details": {
                                "field": "password",
                                "reason": "Password must be at least 8 characters long"
                            }
                        }
                    }
                }
            }
        }
    }
)
async def register(
    request: RegisterRequest,
    session: Session = Depends(get_session)
) -> TokenResponse:
    """
    Register a new user account.
    
    Creates a new user with the provided credentials. Passwords are hashed
    before storage and must meet complexity requirements:
    
    - Minimum 8 characters
    - Must contain at least 3 different character types (uppercase, lowercase, digits, special characters)
    
    Upon successful registration, a JWT token is automatically generated and returned,
    allowing immediate access to protected endpoints.
    
    **No authentication required** - this is a public endpoint.
    
    Args:
        request: Registration request containing username and password
        session: Database session (injected)
        
    Returns:
        TokenResponse with JWT access token
        
    Raises:
        HTTPException 400: If username already exists or password doesn't meet requirements
        
    Requirements: 1.1
    """
    logger.info(f"Registration attempt for username: {request.username}")
    
    auth_service = AuthService()
    user_repo = UserRepository(session)
    
    # Validate password complexity
    is_valid, error_message = auth_service.validate_password_complexity(request.password)
    if not is_valid:
        logger.warning(
            f"Registration failed for username '{request.username}': Password complexity validation failed",
            extra={"username": request.username, "reason": error_message}
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "Password does not meet complexity requirements",
                    "details": {
                        "field": "password",
                        "reason": error_message
                    }
                }
            }
        )
    
    # Hash the password
    hashed_password = auth_service.hash_password(request.password)
    
    # Create user
    user = User(
        username=request.username,
        hashed_password=hashed_password
    )
    
    try:
        created_user = user_repo.create(user)
        logger.info(
            f"User registered successfully: {request.username} (ID: {created_user.id})",
            extra={"username": request.username, "user_id": created_user.id}
        )
    except DuplicateUsernameError:
        logger.warning(
            f"Registration failed for username '{request.username}': Username already exists",
            extra={"username": request.username}
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "Username already exists",
                    "details": {
                        "field": "username",
                        "reason": f"Username '{request.username}' is already taken"
                    }
                }
            }
        )
    
    # Generate JWT token
    access_token = auth_service.create_access_token(created_user.id)
    logger.info(
        f"JWT token generated for user: {request.username}",
        extra={"username": request.username, "user_id": created_user.id}
    )
    
    return TokenResponse(access_token=access_token, token_type="bearer")


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login and receive JWT token",
    response_description="JWT token for authentication",
    responses={
        200: {
            "description": "Login successful",
            "content": {
                "application/json": {
                    "example": {
                        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                        "token_type": "bearer"
                    }
                }
            }
        },
        401: {
            "description": "Authentication failed - invalid credentials",
            "content": {
                "application/json": {
                    "example": {
                        "error": {
                            "code": "AUTHENTICATION_ERROR",
                            "message": "Invalid credentials",
                            "details": {
                                "reason": "Username or password is incorrect"
                            }
                        }
                    }
                }
            }
        }
    }
)
async def login(
    request: LoginRequest,
    session: Session = Depends(get_session)
) -> TokenResponse:
    """
    Authenticate a user and return a JWT token.
    
    Validates user credentials and returns a JWT token on success. The token
    should be included in the `Authorization` header for subsequent requests:
    
    ```
    Authorization: Bearer <your_token>
    ```
    
    Tokens expire after 24 hours by default.
    
    **No authentication required** - this is a public endpoint.
    
    Args:
        request: Login request containing username and password
        session: Database session (injected)
        
    Returns:
        TokenResponse with JWT access token
        
    Raises:
        HTTPException 401: If credentials are invalid
        
    Requirements: 1.2
    """
    logger.info(f"Login attempt for username: {request.username}")
    
    auth_service = AuthService()
    user_repo = UserRepository(session)
    
    # Get user by username
    user = user_repo.get_by_username(request.username)
    
    # Verify user exists and password is correct
    if not user or not auth_service.verify_password(request.password, user.hashed_password):
        logger.warning(
            f"Login failed for username '{request.username}': Invalid credentials",
            extra={"username": request.username}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": {
                    "code": "AUTHENTICATION_ERROR",
                    "message": "Invalid credentials",
                    "details": {
                        "reason": "Username or password is incorrect"
                    }
                }
            }
        )
    
    # Generate JWT token
    access_token = auth_service.create_access_token(user.id)
    logger.info(
        f"Login successful for username: {request.username} (ID: {user.id})",
        extra={"username": request.username, "user_id": user.id}
    )
    
    return TokenResponse(access_token=access_token, token_type="bearer")

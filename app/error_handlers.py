"""
Exception handlers for the License Compliance Scanner.

This module provides FastAPI exception handlers for consistent error responses
across all endpoints.

Requirements: 7.1, 7.2, 7.3
"""

import logging
import traceback
from typing import Union
from fastapi import Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from sqlalchemy.exc import SQLAlchemyError

from app.exceptions import (
    LCSException,
    ValidationError,
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    DatabaseError,
    TimeoutError,
    InternalError
)


# Configure logger
logger = logging.getLogger(__name__)


def create_error_response(
    status_code: int,
    error_code: str,
    message: str,
    details: dict = None
) -> JSONResponse:
    """
    Create a standardized error response.
    
    Args:
        status_code: HTTP status code
        error_code: Application-specific error code
        message: Human-readable error message
        details: Additional error details
        
    Returns:
        JSONResponse with standardized error format
    """
    error_body = {
        "error": {
            "code": error_code,
            "message": message
        }
    }
    
    if details:
        error_body["error"]["details"] = details
    
    return JSONResponse(
        status_code=status_code,
        content=error_body
    )


async def lcs_exception_handler(request: Request, exc: LCSException) -> JSONResponse:
    """
    Handler for custom LCS exceptions.
    
    Maps custom exceptions to appropriate HTTP status codes and formats
    error responses consistently.
    
    Args:
        request: The FastAPI request
        exc: The LCS exception
        
    Returns:
        JSONResponse with error details
        
    Requirements: 7.1, 7.2, 7.3
    """
    # Determine HTTP status code based on exception type
    status_code_map = {
        ValidationError: status.HTTP_400_BAD_REQUEST,
        AuthenticationError: status.HTTP_401_UNAUTHORIZED,
        AuthorizationError: status.HTTP_403_FORBIDDEN,
        NotFoundError: status.HTTP_404_NOT_FOUND,
        DatabaseError: status.HTTP_500_INTERNAL_SERVER_ERROR,
        TimeoutError: status.HTTP_504_GATEWAY_TIMEOUT,
        InternalError: status.HTTP_500_INTERNAL_SERVER_ERROR,
    }
    
    status_code = status_code_map.get(type(exc), status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    # Log error with full context
    log_error(request, exc, status_code)
    
    # For internal errors, don't expose details to client
    if isinstance(exc, (DatabaseError, InternalError)):
        return create_error_response(
            status_code=status_code,
            error_code=exc.code,
            message="An internal error occurred",
            details={"reason": "Please contact support if the problem persists"}
        )
    
    # For other errors, include details
    return create_error_response(
        status_code=status_code,
        error_code=exc.code,
        message=exc.message,
        details=exc.details if exc.details else None
    )


async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError
) -> JSONResponse:
    """
    Handler for Pydantic validation errors.
    
    Converts Pydantic validation errors to our standardized error format
    with specific field-level error messages.
    
    Args:
        request: The FastAPI request
        exc: The validation error
        
    Returns:
        JSONResponse with validation error details
        
    Requirements: 7.2, 7.3
    """
    # Extract validation errors
    errors = exc.errors()
    
    # Format validation errors
    validation_details = []
    for error in errors:
        field = ".".join(str(loc) for loc in error["loc"] if loc != "body")
        validation_details.append({
            "field": field,
            "message": error["msg"],
            "type": error["type"]
        })
    
    # Log validation error
    logger.warning(
        f"Validation error on {request.method} {request.url.path}",
        extra={
            "method": request.method,
            "path": request.url.path,
            "errors": validation_details
        }
    )
    
    return create_error_response(
        status_code=status.HTTP_400_BAD_REQUEST,
        error_code="VALIDATION_ERROR",
        message="Invalid input data",
        details={"validation_errors": validation_details}
    )


async def sqlalchemy_exception_handler(
    request: Request,
    exc: SQLAlchemyError
) -> JSONResponse:
    """
    Handler for SQLAlchemy database errors.
    
    Catches database errors and returns generic error messages to avoid
    exposing internal database details.
    
    Args:
        request: The FastAPI request
        exc: The SQLAlchemy error
        
    Returns:
        JSONResponse with generic error message
        
    Requirements: 7.1, 7.4
    """
    # Log full error details
    logger.error(
        f"Database error on {request.method} {request.url.path}: {str(exc)}",
        extra={
            "method": request.method,
            "path": request.url.path,
            "error_type": type(exc).__name__,
            "traceback": traceback.format_exc()
        }
    )
    
    # Return generic error to client
    return create_error_response(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        error_code="DATABASE_ERROR",
        message="A database error occurred",
        details={"reason": "Please try again later"}
    )


async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Handler for unexpected exceptions.
    
    Catches all unhandled exceptions, logs them with full context,
    and returns a generic error message to avoid exposing internal details.
    
    Args:
        request: The FastAPI request
        exc: The exception
        
    Returns:
        JSONResponse with generic error message
        
    Requirements: 7.1, 7.3
    """
    # Log full error details with stack trace
    logger.error(
        f"Unhandled exception on {request.method} {request.url.path}: {str(exc)}",
        extra={
            "method": request.method,
            "path": request.url.path,
            "error_type": type(exc).__name__,
            "traceback": traceback.format_exc()
        },
        exc_info=True
    )
    
    # Return generic error to client
    return create_error_response(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        error_code="INTERNAL_ERROR",
        message="An internal error occurred",
        details={"reason": "Please contact support if the problem persists"}
    )


def log_error(request: Request, exc: Exception, status_code: int) -> None:
    """
    Log error with full context.
    
    Logs errors with request details, error type, and stack trace for debugging.
    
    Args:
        request: The FastAPI request
        exc: The exception
        status_code: HTTP status code
        
    Requirements: 7.1
    """
    log_level = logging.ERROR if status_code >= 500 else logging.WARNING
    
    logger.log(
        log_level,
        f"{type(exc).__name__} on {request.method} {request.url.path}: {str(exc)}",
        extra={
            "method": request.method,
            "path": request.url.path,
            "status_code": status_code,
            "error_type": type(exc).__name__,
            "error_message": str(exc),
            "traceback": traceback.format_exc() if status_code >= 500 else None
        }
    )

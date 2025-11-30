"""
Custom exception classes for the License Compliance Scanner.

This module defines custom exceptions for different error types to enable
consistent error handling throughout the application.

Requirements: 7.1, 7.2, 7.3
"""


class LCSException(Exception):
    """
    Base exception class for all License Compliance Scanner exceptions.
    
    All custom exceptions should inherit from this class.
    """
    
    def __init__(self, message: str, code: str = "INTERNAL_ERROR", details: dict = None):
        """
        Initialize the exception.
        
        Args:
            message: Human-readable error message
            code: Error code for categorization
            details: Additional error details
        """
        self.message = message
        self.code = code
        self.details = details or {}
        super().__init__(self.message)


class ValidationError(LCSException):
    """
    Exception raised when input validation fails.
    
    HTTP Status: 400 Bad Request
    """
    
    def __init__(self, message: str, field: str = None, reason: str = None):
        """
        Initialize validation error.
        
        Args:
            message: Error message
            field: Field that failed validation
            reason: Specific reason for validation failure
        """
        details = {}
        if field:
            details["field"] = field
        if reason:
            details["reason"] = reason
        
        super().__init__(message, code="VALIDATION_ERROR", details=details)


class AuthenticationError(LCSException):
    """
    Exception raised when authentication fails.
    
    HTTP Status: 401 Unauthorized
    """
    
    def __init__(self, message: str = "Authentication failed", reason: str = None):
        """
        Initialize authentication error.
        
        Args:
            message: Error message
            reason: Specific reason for authentication failure
        """
        details = {}
        if reason:
            details["reason"] = reason
        
        super().__init__(message, code="AUTHENTICATION_ERROR", details=details)


class AuthorizationError(LCSException):
    """
    Exception raised when authorization fails.
    
    HTTP Status: 403 Forbidden
    """
    
    def __init__(self, message: str = "Access denied", reason: str = None):
        """
        Initialize authorization error.
        
        Args:
            message: Error message
            reason: Specific reason for authorization failure
        """
        details = {}
        if reason:
            details["reason"] = reason
        
        super().__init__(message, code="AUTHORIZATION_ERROR", details=details)


class NotFoundError(LCSException):
    """
    Exception raised when a requested resource is not found.
    
    HTTP Status: 404 Not Found
    """
    
    def __init__(self, message: str, resource_type: str = None, resource_id: any = None):
        """
        Initialize not found error.
        
        Args:
            message: Error message
            resource_type: Type of resource that was not found
            resource_id: ID of the resource that was not found
        """
        details = {}
        if resource_type:
            details["resource_type"] = resource_type
        if resource_id is not None:
            details["resource_id"] = resource_id
        
        super().__init__(message, code="NOT_FOUND", details=details)


class DatabaseError(LCSException):
    """
    Exception raised when database operations fail.
    
    HTTP Status: 500 Internal Server Error
    """
    
    def __init__(self, message: str = "Database operation failed", operation: str = None):
        """
        Initialize database error.
        
        Args:
            message: Error message
            operation: Database operation that failed
        """
        details = {}
        if operation:
            details["operation"] = operation
        
        super().__init__(message, code="DATABASE_ERROR", details=details)


class TimeoutError(LCSException):
    """
    Exception raised when a request times out.
    
    HTTP Status: 504 Gateway Timeout
    """
    
    def __init__(self, message: str = "Request timeout", timeout_seconds: int = None):
        """
        Initialize timeout error.
        
        Args:
            message: Error message
            timeout_seconds: Timeout duration in seconds
        """
        details = {}
        if timeout_seconds:
            details["timeout_seconds"] = timeout_seconds
        
        super().__init__(message, code="TIMEOUT_ERROR", details=details)


class InternalError(LCSException):
    """
    Exception raised for unexpected internal errors.
    
    HTTP Status: 500 Internal Server Error
    """
    
    def __init__(self, message: str = "An internal error occurred"):
        """
        Initialize internal error.
        
        Args:
            message: Generic error message (should not expose internal details)
        """
        super().__init__(message, code="INTERNAL_ERROR", details={})

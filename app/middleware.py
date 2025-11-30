"""
Middleware for the License Compliance Scanner.

This module provides middleware for request timeout handling and logging.

Requirements: 7.1, 7.5
"""

import asyncio
import logging
import time
from typing import Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.exceptions import TimeoutError


# Configure logger
logger = logging.getLogger(__name__)


class TimeoutMiddleware(BaseHTTPMiddleware):
    """
    Middleware to enforce request timeouts.
    
    Prevents resource exhaustion by terminating requests that exceed
    the configured timeout threshold.
    
    Requirements: 7.5
    """
    
    def __init__(self, app, timeout_seconds: int = 30):
        """
        Initialize timeout middleware.
        
        Args:
            app: The FastAPI application
            timeout_seconds: Request timeout in seconds (default: 30)
        """
        super().__init__(app)
        self.timeout_seconds = timeout_seconds
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request with timeout enforcement.
        
        Args:
            request: The incoming request
            call_next: The next middleware or route handler
            
        Returns:
            Response from the handler or timeout error
        """
        try:
            # Execute request with timeout
            response = await asyncio.wait_for(
                call_next(request),
                timeout=self.timeout_seconds
            )
            return response
            
        except asyncio.TimeoutError:
            # Log timeout
            logger.warning(
                f"Request timeout on {request.method} {request.url.path}",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "timeout_seconds": self.timeout_seconds
                }
            )
            
            # Return timeout error response
            return JSONResponse(
                status_code=504,
                content={
                    "error": {
                        "code": "TIMEOUT_ERROR",
                        "message": "Request timeout",
                        "details": {
                            "reason": f"Request exceeded {self.timeout_seconds} seconds",
                            "timeout_seconds": self.timeout_seconds
                        }
                    }
                }
            )


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for logging all requests and responses.
    
    Logs request details, response status, and processing time for
    debugging and monitoring.
    
    Requirements: 7.1
    """
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request with logging.
        
        Args:
            request: The incoming request
            call_next: The next middleware or route handler
            
        Returns:
            Response from the handler
        """
        # Record start time
        start_time = time.time()
        
        # Log incoming request
        logger.info(
            f"Incoming request: {request.method} {request.url.path}",
            extra={
                "method": request.method,
                "path": request.url.path,
                "query_params": dict(request.query_params),
                "client_host": request.client.host if request.client else None
            }
        )
        
        # Process request
        response = await call_next(request)
        
        # Calculate processing time
        process_time = time.time() - start_time
        
        # Log response
        log_level = logging.INFO if response.status_code < 400 else logging.WARNING
        logger.log(
            log_level,
            f"Response: {request.method} {request.url.path} - {response.status_code}",
            extra={
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "process_time_seconds": round(process_time, 3)
            }
        )
        
        # Add processing time header
        response.headers["X-Process-Time"] = str(round(process_time, 3))
        
        return response

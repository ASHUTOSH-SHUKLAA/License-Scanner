"""
License Compliance Scanner - Main Application Entry Point

This module initializes and configures the FastAPI application for the
License Compliance Scanner system.
"""

import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from sqlalchemy.exc import SQLAlchemyError

from config import get_settings
from app.database import init_db
from app.routes import auth
# from app.routes import scans
# from app.routes import reports
from app.exceptions import LCSException
from app.error_handlers import (
    lcs_exception_handler,
    validation_exception_handler,
    sqlalchemy_exception_handler,
    generic_exception_handler
)
from app.middleware import TimeoutMiddleware, RequestLoggingMiddleware


# Load configuration
settings = get_settings()

# Configure structured logging based on settings
logging.basicConfig(
    level=getattr(logging, settings.log_level),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()  # Output to stdout
    ]
)

# Create FastAPI application instance
app = FastAPI(
    title="License Compliance Scanner API",
    description="""
## License Compliance Scanner

A backend system for automated license detection and compliance reporting using rule-based pattern matching.

### Features

* **User Authentication**: Secure JWT-based authentication with password complexity requirements
* **License Scanning**: Automated detection of software licenses from text input using pattern matching
* **Compliance Reports**: Structured reports with detected licenses, confidence scores, and warnings
* **Scan History**: Track and retrieve historical scan results with pagination support
* **Rule-Based Detection**: Configurable license detection rules supporting exact matching, keywords, and regex

### Authentication

Most endpoints require authentication using JWT tokens. To authenticate:

1. Register a new account using `POST /api/auth/register`
2. Login to receive a JWT token using `POST /api/auth/login`
3. Include the token in the `Authorization` header: `Bearer <your_token>`

### Workflow

1. **Register/Login** - Create an account or authenticate to receive a JWT token
2. **Submit Scan** - Send license text to `POST /api/scans` for analysis
3. **View Results** - Retrieve scan results from `GET /api/scans/{scan_id}`
4. **Generate Report** - Get a compliance report from `GET /api/reports/{scan_id}`
5. **View History** - List all your scans using `GET /api/scans`

### Rate Limits

* Request timeout: 30 seconds
* Maximum license text size: 1MB
* Pagination limit: 100 records per page
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    contact={
        "name": "License Compliance Scanner Support",
        "email": "support@example.com"
    },
    license_info={
        "name": "MIT License",
        "url": "https://opensource.org/licenses/MIT"
    },
    openapi_tags=[
        {
            "name": "authentication",
            "description": "User registration and login operations. These endpoints do not require authentication."
        },
        {
            "name": "scans",
            "description": "License scanning operations. Submit license text for analysis and retrieve results. **Requires authentication.**"
        },
        {
            "name": "reports",
            "description": "Compliance report generation. Generate structured reports from scan results. **Requires authentication.**"
        }
    ]
)

# Register exception handlers
app.add_exception_handler(LCSException, lcs_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(SQLAlchemyError, sqlalchemy_exception_handler)
app.add_exception_handler(Exception, generic_exception_handler)

# Add middleware (order matters - last added is executed first)
app.add_middleware(TimeoutMiddleware, timeout_seconds=settings.request_timeout_seconds)
app.add_middleware(RequestLoggingMiddleware)

# Include routers
app.include_router(auth.router)
# app.include_router(scans.router)
# app.include_router(reports.router)


@app.on_event("startup")
async def startup_event():
    """
    Initialize application on startup.
    
    Performs configuration validation and database initialization.
    """
    logger = logging.getLogger(__name__)
    
    # Validate configuration
    try:
        logger.info("Validating configuration...")
        validate_configuration()
        logger.info("Configuration validation successful")
    except Exception as e:
        logger.error(f"Configuration validation failed: {e}")
        raise
    
    # Initialize database
    logger.info("Initializing database...")
    init_db()
    logger.info("Database initialized successfully")


def validate_configuration():
    """
    Validate application configuration on startup.
    
    Checks that all required configuration values are present and valid,
    and that required files exist.
    
    Raises:
        FileNotFoundError: If required files don't exist
        ValueError: If configuration is invalid
    """
    from pathlib import Path
    
    # Settings are already validated by Pydantic, but we can do additional checks
    
    # Check that rules file exists
    rules_path = Path(settings.rules_file_path)
    if not rules_path.exists():
        raise FileNotFoundError(
            f"Rules file not found: {settings.rules_file_path}. "
            "Please ensure the rules file exists before starting the application."
        )
    
    # Validate rules file can be loaded
    try:
        from app.license_engine import LicenseEngine
        engine = LicenseEngine(settings.rules_file_path)
        if not engine.rules:
            raise ValueError("Rules file contains no rules")
    except Exception as e:
        raise ValueError(f"Failed to load rules file: {e}")
    
    # Log configuration summary (without sensitive values)
    logger = logging.getLogger(__name__)
    logger.info(f"Database URL: {settings.database_url}")
    logger.info(f"Rules file: {settings.rules_file_path}")
    logger.info(f"Server: {settings.server_host}:{settings.server_port}")
    logger.info(f"Log level: {settings.log_level}")
    logger.info(f"JWT expiration: {settings.jwt_expiration_hours} hours")
    logger.info(f"Request timeout: {settings.request_timeout_seconds} seconds")

# Configure CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get(
    "/",
    tags=["system"],
    summary="Root endpoint",
    response_description="Service information"
)
async def root():
    """
    Get basic service information.
    
    Returns the service name, status, and version. This endpoint can be used
    to verify the API is running and accessible.
    
    Returns:
        dict: Service information including name, status, and version
    """
    return {
        "service": "License Compliance Scanner",
        "status": "running",
        "version": "1.0.0",
        "docs": "/docs",
        "redoc": "/redoc"
    }


@app.get(
    "/health",
    tags=["system"],
    summary="Health check",
    response_description="Health status"
)
async def health_check():
    """
    Check the health status of the API.
    
    This endpoint can be used by monitoring systems to verify the service
    is operational. Returns a simple status indicator.
    
    Returns:
        dict: Health status indicator
    """
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.server_host, port=settings.server_port)

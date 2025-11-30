"""
Configuration management for the License Compliance Scanner.

This module handles loading and validating configuration from environment variables.
All configuration values are centralized here for easy management and validation.

Requirements: 8.1, 8.2
"""

import os
import logging
from typing import Optional
from pydantic import BaseModel, Field, field_validator, ConfigDict


logger = logging.getLogger(__name__)


from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    
    All settings have sensible defaults for development, but should be
    overridden in production via environment variables.
    """
    
    # JWT Configuration
    jwt_secret_key: str = Field(
        default="your-secret-key-here-change-in-production",
        description="Secret key for JWT token signing"
    )
    jwt_algorithm: str = Field(
        default="HS256",
        description="Algorithm for JWT token signing"
    )
    jwt_expiration_hours: int = Field(
        default=24,
        description="JWT token expiration time in hours"
    )
    
    # Database Configuration
    database_url: str = Field(
        default="sqlite:///./lcs.db",
        description="Database connection URL"
    )
    
    # Rules Configuration
    rules_file_path: str = Field(
        default="rules.json",
        description="Path to the license rules JSON file"
    )
    
    # Server Configuration
    server_host: str = Field(
        default="0.0.0.0",
        description="Server host address"
    )
    server_port: int = Field(
        default=8000,
        description="Server port number"
    )
    
    # Logging Configuration
    log_level: str = Field(
        default="INFO",
        description="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)"
    )
    
    # Request timeout configuration
    request_timeout_seconds: int = Field(
        default=30,
        description="Request timeout in seconds"
    )
    
    model_config = ConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False
    )
    
    @field_validator("jwt_secret_key")
    @classmethod
    def validate_jwt_secret_key(cls, v: str) -> str:
        """
        Validate JWT secret key.
        
        In production, the secret key should be changed from the default.
        """
        if v == "your-secret-key-here-change-in-production":
            logger.warning(
                "Using default JWT secret key. "
                "Please set JWT_SECRET_KEY environment variable in production!"
            )
        
        if len(v) < 32:
            logger.warning(
                "JWT secret key is shorter than 32 characters. "
                "Consider using a longer key for better security."
            )
        
        return v
    
    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        """Validate database URL format."""
        if not v:
            raise ValueError("DATABASE_URL cannot be empty")
        
        if v.startswith("postgres://"):
            v = v.replace("postgres://", "postgresql://", 1)
            
        if not v.startswith(("sqlite://", "postgresql://", "mysql://")):
            logger.warning(
                f"Database URL has unexpected format: {v}. "
                "Expected sqlite://, postgresql://, or mysql://"
            )
        
        return v
    
    @field_validator("rules_file_path")
    @classmethod
    def validate_rules_file_path(cls, v: str) -> str:
        """Validate rules file path."""
        if not v:
            raise ValueError("RULES_FILE_PATH cannot be empty")
        
        return v
    
    @field_validator("server_port")
    @classmethod
    def validate_server_port(cls, v: int) -> int:
        """Validate server port is in valid range."""
        if v < 1 or v > 65535:
            raise ValueError(f"Server port must be between 1 and 65535, got {v}")
        
        return v
    
    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level is a valid logging level."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        v_upper = v.upper()
        
        if v_upper not in valid_levels:
            raise ValueError(
                f"LOG_LEVEL must be one of {valid_levels}, got {v}"
            )
        
        return v_upper
    
    @field_validator("jwt_expiration_hours")
    @classmethod
    def validate_jwt_expiration(cls, v: int) -> int:
        """Validate JWT expiration is reasonable."""
        if v < 1:
            raise ValueError("JWT_EXPIRATION_HOURS must be at least 1")
        
        if v > 168:  # 7 days
            logger.warning(
                f"JWT expiration is set to {v} hours (more than 7 days). "
                "Consider using shorter expiration times for better security."
            )
        
        return v
    
    @field_validator("request_timeout_seconds")
    @classmethod
    def validate_request_timeout(cls, v: int) -> int:
        """Validate request timeout is reasonable."""
        if v < 1:
            raise ValueError("REQUEST_TIMEOUT_SECONDS must be at least 1")
        
        if v > 300:  # 5 minutes
            logger.warning(
                f"Request timeout is set to {v} seconds. "
                "Consider using shorter timeouts to prevent resource exhaustion."
            )
        
        return v


def load_settings() -> Settings:
    """
    Load settings from environment variables.
    
    This function reads configuration from environment variables and validates them.
    It should be called once at application startup.
    
    Returns:
        Settings object with validated configuration
        
    Raises:
        ValueError: If any configuration value is invalid
    """
    # Map environment variable names to Settings field names
    env_mapping = {
        "JWT_SECRET_KEY": "jwt_secret_key",
        "JWT_ALGORITHM": "jwt_algorithm",
        "JWT_EXPIRATION_HOURS": "jwt_expiration_hours",
        "DATABASE_URL": "database_url",
        "RULES_FILE_PATH": "rules_file_path",
        "SERVER_HOST": "server_host",
        "SERVER_PORT": "server_port",
        "LOG_LEVEL": "log_level",
        "REQUEST_TIMEOUT_SECONDS": "request_timeout_seconds",
    }
    
    # Build kwargs from environment variables
    kwargs = {}
    for env_var, field_name in env_mapping.items():
        value = os.getenv(env_var)
        if value is not None:
            kwargs[field_name] = value
    
    try:
        settings = Settings(**kwargs)
        logger.info("Configuration loaded successfully")
        return settings
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        raise


# Global settings instance
# This will be initialized when the module is imported
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """
    Get the global settings instance.
    
    This function returns the singleton settings instance. If settings haven't
    been loaded yet, it loads them from environment variables.
    
    Returns:
        Settings object with application configuration
    """
    global _settings
    
    if _settings is None:
        _settings = load_settings()
    
    return _settings


def reload_settings() -> Settings:
    """
    Reload settings from environment variables.
    
    This function forces a reload of settings, useful for testing or
    when environment variables have changed.
    
    Returns:
        Settings object with updated configuration
    """
    global _settings
    _settings = load_settings()
    return _settings

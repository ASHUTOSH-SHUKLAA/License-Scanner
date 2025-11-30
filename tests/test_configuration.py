"""
Tests for configuration management.

This module tests the configuration loading, validation, and environment variable handling.
"""

import os
import pytest
from config import Settings, get_settings, reload_settings


class TestConfigurationLoading:
    """Test configuration loading from environment variables."""
    
    def test_default_settings(self):
        """Test that default settings are loaded correctly."""
        settings = Settings()
        
        assert settings.jwt_algorithm == "HS256"
        assert settings.jwt_expiration_hours == 24
        assert settings.database_url == "sqlite:///./lcs.db"
        assert settings.rules_file_path == "rules.json"
        assert settings.server_host == "0.0.0.0"
        assert settings.server_port == 8000
        assert settings.log_level == "INFO"
        assert settings.request_timeout_seconds == 30
    
    def test_environment_variable_override(self, monkeypatch):
        """Test that environment variables override defaults."""
        monkeypatch.setenv("JWT_EXPIRATION_HOURS", "48")
        monkeypatch.setenv("SERVER_PORT", "9000")
        monkeypatch.setenv("LOG_LEVEL", "DEBUG")
        
        settings = Settings(
            jwt_expiration_hours=48,
            server_port=9000,
            log_level="DEBUG"
        )
        
        assert settings.jwt_expiration_hours == 48
        assert settings.server_port == 9000
        assert settings.log_level == "DEBUG"
    
    def test_get_settings_singleton(self):
        """Test that get_settings returns the same instance."""
        settings1 = get_settings()
        settings2 = get_settings()
        
        assert settings1 is settings2


class TestConfigurationValidation:
    """Test configuration validation."""
    
    def test_invalid_log_level(self):
        """Test that invalid log level raises error."""
        with pytest.raises(ValueError, match="LOG_LEVEL must be one of"):
            Settings(log_level="INVALID")
    
    def test_invalid_server_port_too_low(self):
        """Test that port below 1 raises error."""
        with pytest.raises(ValueError, match="Server port must be between 1 and 65535"):
            Settings(server_port=0)
    
    def test_invalid_server_port_too_high(self):
        """Test that port above 65535 raises error."""
        with pytest.raises(ValueError, match="Server port must be between 1 and 65535"):
            Settings(server_port=70000)
    
    def test_empty_database_url(self):
        """Test that empty database URL raises error."""
        with pytest.raises(ValueError, match="DATABASE_URL cannot be empty"):
            Settings(database_url="")
    
    def test_empty_rules_file_path(self):
        """Test that empty rules file path raises error."""
        with pytest.raises(ValueError, match="RULES_FILE_PATH cannot be empty"):
            Settings(rules_file_path="")
    
    def test_jwt_expiration_too_low(self):
        """Test that JWT expiration below 1 raises error."""
        with pytest.raises(ValueError, match="JWT_EXPIRATION_HOURS must be at least 1"):
            Settings(jwt_expiration_hours=0)
    
    def test_request_timeout_too_low(self):
        """Test that request timeout below 1 raises error."""
        with pytest.raises(ValueError, match="REQUEST_TIMEOUT_SECONDS must be at least 1"):
            Settings(request_timeout_seconds=0)


class TestConfigurationValues:
    """Test specific configuration value handling."""
    
    def test_log_level_case_insensitive(self):
        """Test that log level is case-insensitive."""
        settings = Settings(log_level="debug")
        assert settings.log_level == "DEBUG"
        
        settings = Settings(log_level="Info")
        assert settings.log_level == "INFO"
    
    def test_valid_log_levels(self):
        """Test all valid log levels."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        
        for level in valid_levels:
            settings = Settings(log_level=level)
            assert settings.log_level == level
    
    def test_jwt_secret_key_default(self):
        """Test JWT secret key has a default value."""
        settings = Settings()
        assert settings.jwt_secret_key is not None
        assert len(settings.jwt_secret_key) > 0
    
    def test_custom_jwt_secret_key(self):
        """Test custom JWT secret key."""
        custom_key = "my-super-secret-key-for-testing-purposes-only"
        settings = Settings(jwt_secret_key=custom_key)
        assert settings.jwt_secret_key == custom_key


class TestConfigurationIntegration:
    """Test configuration integration with application."""
    
    def test_settings_used_in_database(self):
        """Test that settings are used in database configuration."""
        from app.database import DATABASE_URL
        settings = get_settings()
        
        assert DATABASE_URL == settings.database_url
    
    def test_settings_used_in_auth_service(self):
        """Test that settings are used in auth service."""
        from app.auth_service import JWT_SECRET_KEY, JWT_ALGORITHM, JWT_EXPIRATION_HOURS
        settings = get_settings()
        
        assert JWT_SECRET_KEY == settings.jwt_secret_key
        assert JWT_ALGORITHM == settings.jwt_algorithm
        assert JWT_EXPIRATION_HOURS == settings.jwt_expiration_hours

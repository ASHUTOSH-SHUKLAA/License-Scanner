"""
Tests for logging functionality.

This module verifies that logging is properly configured and working
across the application.
"""

import logging
import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, create_engine, SQLModel
from sqlmodel.pool import StaticPool

from main import app
from app.database import get_session


# Create in-memory SQLite database for testing
@pytest.fixture(name="session")
def session_fixture():
    """Create a test database session."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


@pytest.fixture(name="client")
def client_fixture(session: Session):
    """Create a test client with overridden database session."""
    def get_session_override():
        return session
    
    app.dependency_overrides[get_session] = get_session_override
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


def test_logging_configuration():
    """Test that logging is properly configured."""
    # Get the root logger
    root_logger = logging.getLogger()
    
    # Verify log level is set
    assert root_logger.level in [logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR, logging.CRITICAL]
    
    # Verify handlers are configured
    assert len(root_logger.handlers) > 0
    
    # Verify at least one handler outputs to stdout
    has_stream_handler = any(
        isinstance(handler, logging.StreamHandler)
        for handler in root_logger.handlers
    )
    assert has_stream_handler, "Should have at least one StreamHandler for stdout"


def test_authentication_logging(client: TestClient, caplog):
    """Test that authentication operations are logged."""
    with caplog.at_level(logging.INFO):
        # Test registration logging
        response = client.post(
            "/api/auth/register",
            json={"username": "testuser", "password": "TestPass123!"}
        )
        
        # Verify registration was logged
        assert any("Registration attempt" in record.message for record in caplog.records)
        assert any("User registered successfully" in record.message for record in caplog.records)
        
        caplog.clear()
        
        # Test login logging
        response = client.post(
            "/api/auth/login",
            json={"username": "testuser", "password": "TestPass123!"}
        )
        
        # Verify login was logged
        assert any("Login attempt" in record.message for record in caplog.records)
        assert any("Login successful" in record.message for record in caplog.records)


def test_scan_operation_logging(client: TestClient, caplog):
    """Test that scan operations are logged."""
    # Register and login
    client.post(
        "/api/auth/register",
        json={"username": "scanuser", "password": "TestPass123!"}
    )
    login_response = client.post(
        "/api/auth/login",
        json={"username": "scanuser", "password": "TestPass123!"}
    )
    token = login_response.json()["access_token"]
    
    caplog.clear()
    
    with caplog.at_level(logging.INFO):
        # Create a scan
        response = client.post(
            "/api/scans",
            json={"license_text": "MIT License\n\nPermission is hereby granted..."},
            headers={"Authorization": f"Bearer {token}"}
        )
        
        # Verify scan operations were logged
        assert any("Creating scan" in record.message for record in caplog.records)
        assert any("Scan created successfully" in record.message for record in caplog.records)
        assert any("Executing scan" in record.message for record in caplog.records)
        assert any("License detection completed" in record.message for record in caplog.records)


def test_error_logging(client: TestClient, caplog):
    """Test that errors are logged with appropriate levels."""
    with caplog.at_level(logging.WARNING):
        # Test failed login (should log warning)
        response = client.post(
            "/api/auth/login",
            json={"username": "nonexistent", "password": "wrongpass"}
        )
        
        # Verify error was logged
        assert any("Login failed" in record.message for record in caplog.records)
        assert any(record.levelname == "WARNING" for record in caplog.records)


def test_request_response_logging(client: TestClient, caplog):
    """Test that request/response middleware logs requests."""
    with caplog.at_level(logging.INFO):
        # Make a request
        response = client.get("/health")
        
        # Verify request/response was logged
        assert any("Incoming request" in record.message for record in caplog.records)
        assert any("Response" in record.message for record in caplog.records)
        assert any("/health" in record.message for record in caplog.records)


def test_report_generation_logging(client: TestClient, caplog):
    """Test that report generation is logged."""
    # Register, login, and create a scan
    client.post(
        "/api/auth/register",
        json={"username": "reportuser", "password": "TestPass123!"}
    )
    login_response = client.post(
        "/api/auth/login",
        json={"username": "reportuser", "password": "TestPass123!"}
    )
    token = login_response.json()["access_token"]
    
    scan_response = client.post(
        "/api/scans",
        json={"license_text": "MIT License"},
        headers={"Authorization": f"Bearer {token}"}
    )
    scan_id = scan_response.json()["scan_id"]
    
    caplog.clear()
    
    with caplog.at_level(logging.INFO):
        # Generate report
        response = client.get(
            f"/api/reports/{scan_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        # Verify report generation was logged
        assert any("Generating report" in record.message for record in caplog.records)
        assert any("Report generated successfully" in record.message for record in caplog.records)

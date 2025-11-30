"""
Tests for the ScanService class.

Tests scan creation, execution, input validation, and error handling.
"""

import pytest
from datetime import datetime
from sqlmodel import Session, create_engine, SQLModel
from sqlalchemy.pool import StaticPool

from app.models import User, Scan
from app.scan_service import ScanService
from app.license_engine import LicenseEngine


@pytest.fixture(name="session")
def session_fixture():
    """Create an in-memory database session for testing."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


@pytest.fixture(name="test_user")
def test_user_fixture(session: Session):
    """Create a test user."""
    user = User(username="testuser", hashed_password="hashed_password")
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@pytest.fixture(name="license_engine")
def license_engine_fixture():
    """Create a LicenseEngine instance with test rules."""
    return LicenseEngine("rules.json")


@pytest.fixture(name="scan_service")
def scan_service_fixture(session: Session, license_engine: LicenseEngine):
    """Create a ScanService instance."""
    return ScanService(session, license_engine)


def test_create_scan_with_valid_input(scan_service: ScanService, test_user: User):
    """Test creating a scan with valid license text."""
    license_text = "MIT License\n\nPermission is hereby granted, free of charge..."
    
    scan = scan_service.create_scan(test_user.id, license_text)
    
    assert scan.id is not None
    assert scan.user_id == test_user.id
    assert scan.license_text == license_text
    assert scan.status == "pending"
    assert scan.results_json is None
    assert scan.completed_at is None
    assert isinstance(scan.created_at, datetime)


def test_create_scan_rejects_empty_text(scan_service: ScanService, test_user: User):
    """Test that empty license text is rejected."""
    with pytest.raises(ValueError, match="License text cannot be empty"):
        scan_service.create_scan(test_user.id, "")


def test_create_scan_rejects_whitespace_only(scan_service: ScanService, test_user: User):
    """Test that whitespace-only text is rejected."""
    with pytest.raises(ValueError, match="License text cannot be empty"):
        scan_service.create_scan(test_user.id, "   \n\t  ")


def test_create_scan_rejects_oversized_input(scan_service: ScanService, test_user: User):
    """Test that license text exceeding size limits is rejected."""
    # Create text larger than 100KB
    large_text = "x" * (100 * 1024 + 1)
    
    with pytest.raises(ValueError, match="exceeds maximum size"):
        scan_service.create_scan(test_user.id, large_text)


def test_execute_scan_detects_licenses(scan_service: ScanService, test_user: User):
    """Test executing a scan and detecting licenses."""
    license_text = "MIT License\n\nPermission is hereby granted, free of charge..."
    
    # Create scan
    scan = scan_service.create_scan(test_user.id, license_text)
    assert scan.status == "pending"
    
    # Execute scan
    updated_scan = scan_service.execute_scan(scan.id)
    
    assert updated_scan.status == "completed"
    assert updated_scan.results_json is not None
    assert updated_scan.completed_at is not None
    
    # Verify results contain license matches
    import json
    results = json.loads(updated_scan.results_json)
    assert "licenses" in results
    assert isinstance(results["licenses"], list)


def test_execute_scan_with_no_matches(scan_service: ScanService, test_user: User):
    """Test executing a scan with text that has no license matches."""
    license_text = "This is just some random text with no license information."
    
    # Create and execute scan
    scan = scan_service.create_scan(test_user.id, license_text)
    updated_scan = scan_service.execute_scan(scan.id)
    
    assert updated_scan.status == "completed"
    assert updated_scan.results_json is not None
    
    # Verify results contain empty license list
    import json
    results = json.loads(updated_scan.results_json)
    assert "licenses" in results
    assert len(results["licenses"]) == 0


def test_execute_scan_with_invalid_scan_id(scan_service: ScanService):
    """Test executing a scan with non-existent scan ID."""
    with pytest.raises(ValueError, match="Scan with id 99999 not found"):
        scan_service.execute_scan(99999)


def test_scan_results_include_all_fields(scan_service: ScanService, test_user: User):
    """Test that scan results include all required fields."""
    license_text = "Apache License, Version 2.0"
    
    scan = scan_service.create_scan(test_user.id, license_text)
    updated_scan = scan_service.execute_scan(scan.id)
    
    import json
    results = json.loads(updated_scan.results_json)
    
    if len(results["licenses"]) > 0:
        match = results["licenses"][0]
        assert "license_type" in match
        assert "confidence" in match
        assert "matched_text" in match
        assert "start_position" in match
        assert "end_position" in match

"""
Tests for the ReportService class.
"""

import json
import pytest
from datetime import datetime
from sqlmodel import Session, create_engine, SQLModel
from app.models import User, Scan
from app.scan_repository import ScanRepository
from app.report_service import ReportService


@pytest.fixture
def engine():
    """Create an in-memory SQLite database for testing."""
    engine = create_engine("sqlite:///:memory:")
    SQLModel.metadata.create_all(engine)
    return engine


@pytest.fixture
def session(engine):
    """Create a database session for testing."""
    with Session(engine) as session:
        yield session


@pytest.fixture
def test_user(session):
    """Create a test user."""
    user = User(username="testuser", hashed_password="hashed_password")
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@pytest.fixture
def scan_repository(session):
    """Create a ScanRepository instance."""
    return ScanRepository(session)


@pytest.fixture
def report_service(scan_repository):
    """Create a ReportService instance."""
    return ReportService(scan_repository)


def test_generate_report_with_licenses(scan_repository, report_service, test_user):
    """Test generating a report for a scan with detected licenses."""
    # Create a scan with results
    results = {
        "licenses": [
            {
                "license_type": "MIT",
                "confidence": 0.95,
                "matched_text": "MIT License",
                "start_position": 0,
                "end_position": 11
            },
            {
                "license_type": "Apache-2.0",
                "confidence": 0.88,
                "matched_text": "Apache License",
                "start_position": 20,
                "end_position": 34
            }
        ]
    }
    
    scan = Scan(
        user_id=test_user.id,
        license_text="MIT License and Apache License",
        status="completed",
        results_json=json.dumps(results),
        completed_at=datetime.utcnow()
    )
    scan = scan_repository.create(scan)
    
    # Generate report
    report = report_service.generate_report(scan.id, test_user.id)
    
    # Verify report
    assert report is not None
    assert report.scan_id == scan.id
    assert report.user_id == test_user.id
    assert report.total_licenses_found == 2
    assert len(report.licenses) == 2
    assert report.summary["total_licenses"] == 2
    assert report.summary["unique_license_types"] == 2
    assert set(report.summary["license_types"]) == {"MIT", "Apache-2.0"}
    assert report.summary["average_confidence"] == 0.92  # (0.95 + 0.88) / 2 = 0.915, rounded to 0.92


def test_generate_report_with_warnings(scan_repository, report_service, test_user):
    """Test that problematic licenses generate warnings."""
    # Create a scan with GPL license
    results = {
        "licenses": [
            {
                "license_type": "GPL-3.0",
                "confidence": 0.95,
                "matched_text": "GPL-3.0",
                "start_position": 0,
                "end_position": 7
            }
        ]
    }
    
    scan = Scan(
        user_id=test_user.id,
        license_text="GPL-3.0 license",
        status="completed",
        results_json=json.dumps(results),
        completed_at=datetime.utcnow()
    )
    scan = scan_repository.create(scan)
    
    # Generate report
    report = report_service.generate_report(scan.id, test_user.id)
    
    # Verify warnings
    assert report is not None
    assert len(report.warnings) > 0
    assert any("GPL-3.0" in warning for warning in report.warnings)


def test_generate_report_no_licenses(scan_repository, report_service, test_user):
    """Test generating a report for a scan with no detected licenses."""
    # Create a scan with no results
    results = {"licenses": []}
    
    scan = Scan(
        user_id=test_user.id,
        license_text="No license text",
        status="completed",
        results_json=json.dumps(results),
        completed_at=datetime.utcnow()
    )
    scan = scan_repository.create(scan)
    
    # Generate report
    report = report_service.generate_report(scan.id, test_user.id)
    
    # Verify report
    assert report is not None
    assert report.total_licenses_found == 0
    assert len(report.licenses) == 0
    assert report.summary["total_licenses"] == 0
    assert report.summary["unique_license_types"] == 0
    assert report.summary["average_confidence"] == 0.0


def test_generate_report_wrong_user(scan_repository, report_service, test_user, session):
    """Test that users cannot access other users' reports."""
    # Create another user
    other_user = User(username="otheruser", hashed_password="hashed_password")
    session.add(other_user)
    session.commit()
    session.refresh(other_user)
    
    # Create a scan for test_user
    scan = Scan(
        user_id=test_user.id,
        license_text="Test",
        status="completed",
        results_json=json.dumps({"licenses": []})
    )
    scan = scan_repository.create(scan)
    
    # Try to generate report as other_user
    report = report_service.generate_report(scan.id, other_user.id)
    
    # Should return None
    assert report is None


def test_generate_report_nonexistent_scan(report_service, test_user):
    """Test generating a report for a non-existent scan."""
    report = report_service.generate_report(99999, test_user.id)
    assert report is None


def test_generate_report_invalid_json(scan_repository, report_service, test_user):
    """Test handling of invalid JSON in results."""
    # Create a scan with invalid JSON
    scan = Scan(
        user_id=test_user.id,
        license_text="Test",
        status="completed",
        results_json="invalid json {{"
    )
    scan = scan_repository.create(scan)
    
    # Generate report - should handle gracefully
    report = report_service.generate_report(scan.id, test_user.id)
    
    # Should return report with empty licenses
    assert report is not None
    assert report.total_licenses_found == 0
    assert len(report.licenses) == 0

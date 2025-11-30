"""
Tests for the ScanRepository class.

This module tests CRUD operations, pagination, filtering, and ordering for scans.
"""

import pytest
from datetime import datetime, timedelta
from sqlmodel import Session, create_engine, SQLModel
from app.models import User, Scan
from app.scan_repository import ScanRepository


@pytest.fixture
def in_memory_session():
    """Create an in-memory SQLite database session for testing."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    
    with Session(engine) as session:
        yield session


@pytest.fixture
def test_user(in_memory_session):
    """Create a test user."""
    user = User(username="testuser", hashed_password="hashed_password")
    in_memory_session.add(user)
    in_memory_session.commit()
    in_memory_session.refresh(user)
    return user


@pytest.fixture
def another_user(in_memory_session):
    """Create another test user."""
    user = User(username="anotheruser", hashed_password="hashed_password")
    in_memory_session.add(user)
    in_memory_session.commit()
    in_memory_session.refresh(user)
    return user


@pytest.fixture
def scan_repository(in_memory_session):
    """Create a ScanRepository instance."""
    return ScanRepository(in_memory_session)


def test_create_scan(scan_repository, test_user):
    """Test creating a new scan."""
    scan = Scan(
        user_id=test_user.id,
        license_text="MIT License",
        status="pending"
    )
    
    created_scan = scan_repository.create(scan)
    
    assert created_scan.id is not None
    assert created_scan.user_id == test_user.id
    assert created_scan.license_text == "MIT License"
    assert created_scan.status == "pending"
    assert created_scan.created_at is not None


def test_get_by_id(scan_repository, test_user):
    """Test retrieving a scan by ID."""
    scan = Scan(
        user_id=test_user.id,
        license_text="Apache License",
        status="pending"
    )
    created_scan = scan_repository.create(scan)
    
    retrieved_scan = scan_repository.get_by_id(created_scan.id)
    
    assert retrieved_scan is not None
    assert retrieved_scan.id == created_scan.id
    assert retrieved_scan.license_text == "Apache License"


def test_get_by_id_not_found(scan_repository):
    """Test retrieving a non-existent scan returns None."""
    result = scan_repository.get_by_id(99999)
    assert result is None


def test_get_by_user_filters_by_user(scan_repository, test_user, another_user):
    """Test that get_by_user only returns scans for the specified user."""
    # Create scans for test_user
    scan1 = Scan(user_id=test_user.id, license_text="MIT", status="pending")
    scan2 = Scan(user_id=test_user.id, license_text="Apache", status="pending")
    scan_repository.create(scan1)
    scan_repository.create(scan2)
    
    # Create scan for another_user
    scan3 = Scan(user_id=another_user.id, license_text="GPL", status="pending")
    scan_repository.create(scan3)
    
    # Get scans for test_user
    user_scans = scan_repository.get_by_user(test_user.id)
    
    assert len(user_scans) == 2
    assert all(scan.user_id == test_user.id for scan in user_scans)


def test_get_by_user_chronological_ordering(scan_repository, test_user, in_memory_session):
    """Test that scans are returned in chronological order (most recent first)."""
    # Create scans with different timestamps
    now = datetime.utcnow()
    
    scan1 = Scan(user_id=test_user.id, license_text="Old", status="pending")
    scan1.created_at = now - timedelta(hours=2)
    in_memory_session.add(scan1)
    in_memory_session.commit()
    
    scan2 = Scan(user_id=test_user.id, license_text="Recent", status="pending")
    scan2.created_at = now
    in_memory_session.add(scan2)
    in_memory_session.commit()
    
    scan3 = Scan(user_id=test_user.id, license_text="Middle", status="pending")
    scan3.created_at = now - timedelta(hours=1)
    in_memory_session.add(scan3)
    in_memory_session.commit()
    
    # Get scans
    scans = scan_repository.get_by_user(test_user.id)
    
    assert len(scans) == 3
    assert scans[0].license_text == "Recent"
    assert scans[1].license_text == "Middle"
    assert scans[2].license_text == "Old"


def test_get_by_user_pagination(scan_repository, test_user):
    """Test pagination with skip and limit parameters."""
    # Create 5 scans
    for i in range(5):
        scan = Scan(user_id=test_user.id, license_text=f"License {i}", status="pending")
        scan_repository.create(scan)
    
    # Get first page (2 items)
    page1 = scan_repository.get_by_user(test_user.id, skip=0, limit=2)
    assert len(page1) == 2
    
    # Get second page (2 items)
    page2 = scan_repository.get_by_user(test_user.id, skip=2, limit=2)
    assert len(page2) == 2
    
    # Get third page (1 item)
    page3 = scan_repository.get_by_user(test_user.id, skip=4, limit=2)
    assert len(page3) == 1
    
    # Verify no overlap
    page1_ids = {scan.id for scan in page1}
    page2_ids = {scan.id for scan in page2}
    page3_ids = {scan.id for scan in page3}
    
    assert len(page1_ids & page2_ids) == 0
    assert len(page1_ids & page3_ids) == 0
    assert len(page2_ids & page3_ids) == 0


def test_update_results(scan_repository, test_user):
    """Test updating scan results."""
    scan = Scan(user_id=test_user.id, license_text="MIT License", status="pending")
    created_scan = scan_repository.create(scan)
    
    results = {
        "licenses": [
            {"type": "MIT", "confidence": 0.95}
        ]
    }
    
    updated_scan = scan_repository.update_results(created_scan.id, results)
    
    assert updated_scan is not None
    assert updated_scan.status == "completed"
    assert updated_scan.results_json is not None
    assert "MIT" in updated_scan.results_json
    assert updated_scan.completed_at is not None


def test_update_results_not_found(scan_repository):
    """Test updating results for non-existent scan returns None."""
    results = {"licenses": []}
    result = scan_repository.update_results(99999, results)
    assert result is None


def test_get_by_user_empty_result(scan_repository, test_user):
    """Test that get_by_user returns empty list when user has no scans."""
    scans = scan_repository.get_by_user(test_user.id)
    assert scans == []

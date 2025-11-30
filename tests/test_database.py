"""
Tests for database models and initialization.
"""

import pytest
from datetime import datetime
from sqlmodel import Session, create_engine, SQLModel
from app.models import User, Scan
from app.database import init_db


@pytest.fixture
def test_engine():
    """Create an in-memory SQLite database for testing."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    return engine


@pytest.fixture
def test_session(test_engine):
    """Create a test database session."""
    with Session(test_engine) as session:
        yield session


def test_user_model_creation(test_session):
    """Test that User model can be created and stored."""
    user = User(
        username="testuser",
        hashed_password="hashed_password_123"
    )
    
    test_session.add(user)
    test_session.commit()
    test_session.refresh(user)
    
    assert user.id is not None
    assert user.username == "testuser"
    assert user.hashed_password == "hashed_password_123"
    assert isinstance(user.created_at, datetime)


def test_scan_model_creation(test_session):
    """Test that Scan model can be created and stored."""
    # First create a user
    user = User(username="scanuser", hashed_password="hashed_pass")
    test_session.add(user)
    test_session.commit()
    test_session.refresh(user)
    
    # Create a scan
    scan = Scan(
        user_id=user.id,
        license_text="MIT License text here",
        status="pending"
    )
    
    test_session.add(scan)
    test_session.commit()
    test_session.refresh(scan)
    
    assert scan.id is not None
    assert scan.user_id == user.id
    assert scan.license_text == "MIT License text here"
    assert scan.status == "pending"
    assert scan.results_json is None
    assert isinstance(scan.created_at, datetime)
    assert scan.completed_at is None


def test_user_username_unique_constraint(test_session):
    """Test that username must be unique."""
    user1 = User(username="duplicate", hashed_password="pass1")
    test_session.add(user1)
    test_session.commit()
    
    # Try to create another user with the same username
    user2 = User(username="duplicate", hashed_password="pass2")
    test_session.add(user2)
    
    with pytest.raises(Exception):  # SQLite will raise an IntegrityError
        test_session.commit()


def test_scan_foreign_key_relationship(test_session):
    """Test that scan.user_id references a valid user."""
    user = User(username="fkuser", hashed_password="pass")
    test_session.add(user)
    test_session.commit()
    test_session.refresh(user)
    
    scan = Scan(
        user_id=user.id,
        license_text="Test license",
        status="pending"
    )
    test_session.add(scan)
    test_session.commit()
    
    # Verify the relationship
    retrieved_scan = test_session.get(Scan, scan.id)
    assert retrieved_scan.user_id == user.id


def test_scan_status_values(test_session):
    """Test that scan can have different status values."""
    user = User(username="statususer", hashed_password="pass")
    test_session.add(user)
    test_session.commit()
    test_session.refresh(user)
    
    statuses = ["pending", "completed", "failed"]
    
    for status in statuses:
        scan = Scan(
            user_id=user.id,
            license_text="Test",
            status=status
        )
        test_session.add(scan)
        test_session.commit()
        test_session.refresh(scan)
        assert scan.status == status


def test_scan_with_results(test_session):
    """Test that scan can store results_json and completed_at."""
    user = User(username="resultuser", hashed_password="pass")
    test_session.add(user)
    test_session.commit()
    test_session.refresh(user)
    
    completed_time = datetime.utcnow()
    scan = Scan(
        user_id=user.id,
        license_text="Test",
        status="completed",
        results_json='{"licenses": [{"type": "MIT"}]}',
        completed_at=completed_time
    )
    
    test_session.add(scan)
    test_session.commit()
    test_session.refresh(scan)
    
    assert scan.results_json == '{"licenses": [{"type": "MIT"}]}'
    assert scan.completed_at == completed_time

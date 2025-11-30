"""
Tests for the UserRepository class.

This module tests CRUD operations for users including duplicate username handling.
"""

import pytest
from datetime import datetime
from sqlmodel import Session, create_engine, SQLModel
from app.models import User
from app.user_repository import UserRepository, DuplicateUsernameError


@pytest.fixture
def in_memory_session():
    """Create an in-memory SQLite database session for testing."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


def test_create_user(in_memory_session):
    """Test creating a new user."""
    repo = UserRepository(in_memory_session)
    
    user = User(
        username="testuser",
        hashed_password="hashed_password_123"
    )
    
    created_user = repo.create(user)
    
    assert created_user.id is not None
    assert created_user.username == "testuser"
    assert created_user.hashed_password == "hashed_password_123"
    assert isinstance(created_user.created_at, datetime)


def test_get_by_username(in_memory_session):
    """Test retrieving a user by username."""
    repo = UserRepository(in_memory_session)
    
    # Create a user
    user = User(username="findme", hashed_password="password123")
    repo.create(user)
    
    # Retrieve by username
    found_user = repo.get_by_username("findme")
    
    assert found_user is not None
    assert found_user.username == "findme"
    assert found_user.hashed_password == "password123"


def test_get_by_username_not_found(in_memory_session):
    """Test retrieving a non-existent user returns None."""
    repo = UserRepository(in_memory_session)
    
    found_user = repo.get_by_username("nonexistent")
    
    assert found_user is None


def test_get_by_id(in_memory_session):
    """Test retrieving a user by ID."""
    repo = UserRepository(in_memory_session)
    
    # Create a user
    user = User(username="idtest", hashed_password="password123")
    created_user = repo.create(user)
    
    # Retrieve by ID
    found_user = repo.get_by_id(created_user.id)
    
    assert found_user is not None
    assert found_user.id == created_user.id
    assert found_user.username == "idtest"


def test_get_by_id_not_found(in_memory_session):
    """Test retrieving a non-existent user by ID returns None."""
    repo = UserRepository(in_memory_session)
    
    found_user = repo.get_by_id(99999)
    
    assert found_user is None


def test_duplicate_username_raises_error(in_memory_session):
    """Test that creating a user with duplicate username raises DuplicateUsernameError."""
    repo = UserRepository(in_memory_session)
    
    # Create first user
    user1 = User(username="duplicate", hashed_password="password1")
    repo.create(user1)
    
    # Attempt to create second user with same username
    user2 = User(username="duplicate", hashed_password="password2")
    
    with pytest.raises(DuplicateUsernameError) as exc_info:
        repo.create(user2)
    
    assert "duplicate" in str(exc_info.value)
    assert exc_info.value.username == "duplicate"


def test_session_rollback_on_duplicate(in_memory_session):
    """Test that session is rolled back on duplicate username error."""
    repo = UserRepository(in_memory_session)
    
    # Create first user
    user1 = User(username="rollbacktest", hashed_password="password1")
    repo.create(user1)
    
    # Attempt to create duplicate
    user2 = User(username="rollbacktest", hashed_password="password2")
    
    try:
        repo.create(user2)
    except DuplicateUsernameError:
        pass
    
    # Verify we can still use the session
    user3 = User(username="afterrollback", hashed_password="password3")
    created_user = repo.create(user3)
    
    assert created_user.id is not None
    assert created_user.username == "afterrollback"

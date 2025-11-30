"""
Tests for application startup and database initialization.
"""

import os
import pytest
from fastapi.testclient import TestClient
from sqlmodel import create_engine, SQLModel, Session
from app.models import User, Scan


def test_database_initialization():
    """Test that database initialization creates tables correctly."""
    # Create an in-memory database for testing
    from app.database import init_db
    
    test_engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    
    # Manually create tables
    SQLModel.metadata.create_all(test_engine)
    
    # Verify we can create and query data
    with Session(test_engine) as session:
        user = User(username="testuser", hashed_password="hashed")
        session.add(user)
        session.commit()
        session.refresh(user)
        
        assert user.id is not None
        assert user.username == "testuser"
        
        scan = Scan(
            user_id=user.id,
            license_text="Test license",
            status="pending"
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)
        
        assert scan.id is not None
        assert scan.user_id == user.id


def test_health_endpoint():
    """Test that the health endpoint works after database initialization."""
    from main import app
    
    client = TestClient(app)
    response = client.get("/health")
    
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}
    
    client.close()

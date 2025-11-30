"""
Tests for report API endpoints.

This module tests the compliance report generation endpoint.

Requirements: 5.1, 5.2, 5.3, 5.4, 5.5
"""

import pytest
import json
from fastapi.testclient import TestClient
from sqlmodel import Session, create_engine, SQLModel
from sqlmodel.pool import StaticPool
from datetime import datetime

from main import app
from app.database import get_session
from app.models import User, Scan
from app.auth_service import AuthService


# Create in-memory database for testing
@pytest.fixture(name="session")
def session_fixture():
    """Create a test database session."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


@pytest.fixture(name="client")
def client_fixture(session: Session):
    """Create a test client with database session override."""
    def get_session_override():
        return session
    
    app.dependency_overrides[get_session] = get_session_override
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


@pytest.fixture(name="test_user")
def test_user_fixture(session: Session):
    """Create a test user and return user with token."""
    auth_service = AuthService()
    hashed_password = auth_service.hash_password("TestPass123!")
    
    user = User(
        username="testuser",
        hashed_password=hashed_password,
        created_at=datetime.utcnow()
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    
    # Generate token
    token = auth_service.create_access_token(user.id)
    
    return {"user": user, "token": token}


@pytest.fixture(name="test_user2")
def test_user2_fixture(session: Session):
    """Create a second test user."""
    auth_service = AuthService()
    hashed_password = auth_service.hash_password("TestPass456!")
    
    user = User(
        username="testuser2",
        hashed_password=hashed_password,
        created_at=datetime.utcnow()
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    
    # Generate token
    token = auth_service.create_access_token(user.id)
    
    return {"user": user, "token": token}


class TestGetReport:
    """Tests for GET /api/reports/{scan_id} endpoint."""
    
    def test_get_report_success(self, client: TestClient, session: Session, test_user: dict):
        """Test successful report generation for a completed scan."""
        # Create a scan with results
        results = {
            "licenses": [
                {
                    "license_type": "MIT",
                    "confidence": 0.95,
                    "matched_text": "MIT License",
                    "start_position": 0,
                    "end_position": 11
                }
            ]
        }
        
        scan = Scan(
            user_id=test_user["user"].id,
            license_text="MIT License\n\nPermission is hereby granted",
            status="completed",
            results_json=json.dumps(results),
            created_at=datetime.utcnow(),
            completed_at=datetime.utcnow()
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)
        
        # Get report
        response = client.get(
            f"/api/reports/{scan.id}",
            headers={"Authorization": f"Bearer {test_user['token']}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify report structure
        assert data["scan_id"] == scan.id
        assert data["user_id"] == test_user["user"].id
        assert "timestamp" in data
        assert data["total_licenses_found"] == 1
        assert len(data["licenses"]) == 1
        assert data["licenses"][0]["license_type"] == "MIT"
        assert "summary" in data
        assert "warnings" in data
    
    def test_get_report_with_warnings(self, client: TestClient, session: Session, test_user: dict):
        """Test report generation includes warnings for problematic licenses."""
        # Create a scan with GPL license (should trigger warning)
        results = {
            "licenses": [
                {
                    "license_type": "GPL-3.0",
                    "confidence": 0.90,
                    "matched_text": "GNU General Public License v3.0",
                    "start_position": 0,
                    "end_position": 30
                }
            ]
        }
        
        scan = Scan(
            user_id=test_user["user"].id,
            license_text="GNU General Public License v3.0",
            status="completed",
            results_json=json.dumps(results),
            created_at=datetime.utcnow(),
            completed_at=datetime.utcnow()
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)
        
        # Get report
        response = client.get(
            f"/api/reports/{scan.id}",
            headers={"Authorization": f"Bearer {test_user['token']}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify warning is present
        assert len(data["warnings"]) > 0
        assert any("GPL-3.0" in warning for warning in data["warnings"])
    
    def test_get_report_not_found(self, client: TestClient, test_user: dict):
        """Test report request for non-existent scan returns 404."""
        response = client.get(
            "/api/reports/99999",
            headers={"Authorization": f"Bearer {test_user['token']}"}
        )
        
        assert response.status_code == 404
        data = response.json()
        assert "detail" in data
        assert data["detail"]["error"]["code"] == "NOT_FOUND"
    
    def test_get_report_unauthorized_access(self, client: TestClient, session: Session, test_user: dict, test_user2: dict):
        """Test user cannot access another user's report."""
        # Create scan for user1
        scan = Scan(
            user_id=test_user["user"].id,
            license_text="MIT License",
            status="completed",
            results_json=json.dumps({"licenses": []}),
            created_at=datetime.utcnow(),
            completed_at=datetime.utcnow()
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)
        
        # Try to access with user2's token
        response = client.get(
            f"/api/reports/{scan.id}",
            headers={"Authorization": f"Bearer {test_user2['token']}"}
        )
        
        assert response.status_code == 403
        data = response.json()
        assert "detail" in data
        assert data["detail"]["error"]["code"] == "AUTHORIZATION_ERROR"
    
    def test_get_report_without_auth(self, client: TestClient, session: Session, test_user: dict):
        """Test report request without authentication returns 401."""
        # Create a scan
        scan = Scan(
            user_id=test_user["user"].id,
            license_text="MIT License",
            status="completed",
            results_json=json.dumps({"licenses": []}),
            created_at=datetime.utcnow()
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)
        
        # Try to access without token
        response = client.get(f"/api/reports/{scan.id}")
        
        assert response.status_code == 403  # FastAPI returns 403 for missing auth

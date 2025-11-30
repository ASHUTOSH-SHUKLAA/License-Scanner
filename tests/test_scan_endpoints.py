"""
Tests for scan API endpoints.

This module tests the scan submission, retrieval, and history endpoints.

Requirements: 2.1, 2.4, 4.1, 4.2, 4.3, 6.1, 6.2, 6.3, 6.5
"""

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, create_engine, SQLModel
from sqlmodel.pool import StaticPool

from main import app
from app.database import get_session
from app.models import User, Scan
from app.auth_service import AuthService
from datetime import datetime


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


class TestCreateScan:
    """Tests for POST /api/scans endpoint."""
    
    def test_create_scan_success(self, client: TestClient, test_user: dict):
        """Test successful scan creation with valid license text."""
        response = client.post(
            "/api/scans",
            json={"license_text": "MIT License\n\nPermission is hereby granted, free of charge"},
            headers={"Authorization": f"Bearer {test_user['token']}"}
        )
        
        assert response.status_code == 201
        data = response.json()
        
        assert "scan_id" in data
        assert data["status"] == "completed"
        assert "licenses" in data
        assert "created_at" in data
        assert isinstance(data["licenses"], list)
    
    def test_create_scan_detects_licenses(self, client: TestClient, test_user: dict):
        """Test that scan actually detects licenses in the text."""
        response = client.post(
            "/api/scans",
            json={"license_text": "This software is licensed under the MIT License"},
            headers={"Authorization": f"Bearer {test_user['token']}"}
        )
        
        assert response.status_code == 201
        data = response.json()
        
        # Should detect MIT license
        assert len(data["licenses"]) > 0
        license_types = [lic["license_type"] for lic in data["licenses"]]
        assert "MIT" in license_types
    
    def test_create_scan_without_auth(self, client: TestClient):
        """Test that scan creation requires authentication."""
        response = client.post(
            "/api/scans",
            json={"license_text": "Some license text"}
        )
        
        assert response.status_code == 403  # FastAPI returns 403 for missing auth
    
    def test_create_scan_with_invalid_token(self, client: TestClient):
        """Test scan creation with invalid token."""
        response = client.post(
            "/api/scans",
            json={"license_text": "Some license text"},
            headers={"Authorization": "Bearer invalid_token"}
        )
        
        assert response.status_code == 401
    
    def test_create_scan_empty_text(self, client: TestClient, test_user: dict):
        """Test that empty license text is rejected."""
        response = client.post(
            "/api/scans",
            json={"license_text": ""},
            headers={"Authorization": f"Bearer {test_user['token']}"}
        )
        
        # Validation errors return 400 with our custom error handler
        assert response.status_code == 400
    
    def test_create_scan_whitespace_only(self, client: TestClient, test_user: dict):
        """Test that whitespace-only text is rejected."""
        response = client.post(
            "/api/scans",
            json={"license_text": "   \n\t  "},
            headers={"Authorization": f"Bearer {test_user['token']}"}
        )
        
        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        assert "error" in data["detail"]
    
    def test_create_scan_oversized_input(self, client: TestClient, test_user: dict):
        """Test that oversized input is rejected."""
        # Create text larger than 100KB
        large_text = "x" * (101 * 1024)
        
        response = client.post(
            "/api/scans",
            json={"license_text": large_text},
            headers={"Authorization": f"Bearer {test_user['token']}"}
        )
        
        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        assert "error" in data["detail"]


class TestGetScan:
    """Tests for GET /api/scans/{scan_id} endpoint."""
    
    def test_get_scan_success(self, client: TestClient, test_user: dict, session: Session):
        """Test successful retrieval of a scan."""
        # Create a scan first
        scan = Scan(
            user_id=test_user["user"].id,
            license_text="MIT License",
            status="completed",
            results_json='{"licenses": [{"license_type": "MIT", "confidence": 0.95, "matched_text": "MIT License", "start_position": 0, "end_position": 11}]}',
            created_at=datetime.utcnow(),
            completed_at=datetime.utcnow()
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)
        
        # Retrieve the scan
        response = client.get(
            f"/api/scans/{scan.id}",
            headers={"Authorization": f"Bearer {test_user['token']}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["scan_id"] == scan.id
        assert data["status"] == "completed"
        assert len(data["licenses"]) == 1
        assert data["licenses"][0]["license_type"] == "MIT"
    
    def test_get_scan_not_found(self, client: TestClient, test_user: dict):
        """Test retrieval of non-existent scan."""
        response = client.get(
            "/api/scans/99999",
            headers={"Authorization": f"Bearer {test_user['token']}"}
        )
        
        assert response.status_code == 404
        data = response.json()
        assert "detail" in data
        assert "error" in data["detail"]
    
    def test_get_scan_unauthorized_access(self, client: TestClient, test_user: dict, test_user2: dict, session: Session):
        """Test that users cannot access other users' scans."""
        # Create a scan for user1
        scan = Scan(
            user_id=test_user["user"].id,
            license_text="MIT License",
            status="completed",
            results_json='{"licenses": []}',
            created_at=datetime.utcnow()
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)
        
        # Try to access with user2's token
        response = client.get(
            f"/api/scans/{scan.id}",
            headers={"Authorization": f"Bearer {test_user2['token']}"}
        )
        
        assert response.status_code == 403
        data = response.json()
        assert "detail" in data
        assert "error" in data["detail"]
    
    def test_get_scan_without_auth(self, client: TestClient, session: Session):
        """Test that scan retrieval requires authentication."""
        # Create a scan
        scan = Scan(
            user_id=1,
            license_text="MIT License",
            status="completed",
            results_json='{"licenses": []}',
            created_at=datetime.utcnow()
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)
        
        response = client.get(f"/api/scans/{scan.id}")
        
        assert response.status_code == 403


class TestGetScanHistory:
    """Tests for GET /api/scans endpoint."""
    
    def test_get_scan_history_empty(self, client: TestClient, test_user: dict):
        """Test scan history when user has no scans."""
        response = client.get(
            "/api/scans",
            headers={"Authorization": f"Bearer {test_user['token']}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 0
    
    def test_get_scan_history_with_scans(self, client: TestClient, test_user: dict, session: Session):
        """Test scan history returns user's scans."""
        # Create multiple scans
        for i in range(3):
            scan = Scan(
                user_id=test_user["user"].id,
                license_text=f"License text {i}",
                status="completed",
                results_json='{"licenses": []}',
                created_at=datetime.utcnow()
            )
            session.add(scan)
        session.commit()
        
        response = client.get(
            "/api/scans",
            headers={"Authorization": f"Bearer {test_user['token']}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 3
        
        # Check metadata fields are present
        for scan_data in data:
            assert "scan_id" in scan_data
            assert "status" in scan_data
            assert "created_at" in scan_data
            # Should NOT include full results
            assert "results_json" not in scan_data
            assert "license_text" not in scan_data
    
    def test_get_scan_history_user_isolation(self, client: TestClient, test_user: dict, test_user2: dict, session: Session):
        """Test that users only see their own scans."""
        # Create scans for user1
        for i in range(2):
            scan = Scan(
                user_id=test_user["user"].id,
                license_text=f"User1 license {i}",
                status="completed",
                results_json='{"licenses": []}',
                created_at=datetime.utcnow()
            )
            session.add(scan)
        
        # Create scans for user2
        for i in range(3):
            scan = Scan(
                user_id=test_user2["user"].id,
                license_text=f"User2 license {i}",
                status="completed",
                results_json='{"licenses": []}',
                created_at=datetime.utcnow()
            )
            session.add(scan)
        session.commit()
        
        # User1 should only see their 2 scans
        response = client.get(
            "/api/scans",
            headers={"Authorization": f"Bearer {test_user['token']}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        
        # User2 should only see their 3 scans
        response = client.get(
            "/api/scans",
            headers={"Authorization": f"Bearer {test_user2['token']}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 3
    
    def test_get_scan_history_pagination(self, client: TestClient, test_user: dict, session: Session):
        """Test pagination of scan history."""
        # Create 15 scans
        for i in range(15):
            scan = Scan(
                user_id=test_user["user"].id,
                license_text=f"License text {i}",
                status="completed",
                results_json='{"licenses": []}',
                created_at=datetime.utcnow()
            )
            session.add(scan)
        session.commit()
        
        # Get first page (default limit is 10)
        response = client.get(
            "/api/scans",
            headers={"Authorization": f"Bearer {test_user['token']}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 10
        
        # Get second page
        response = client.get(
            "/api/scans?skip=10&limit=10",
            headers={"Authorization": f"Bearer {test_user['token']}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 5
        
        # Get with custom page size
        response = client.get(
            "/api/scans?skip=0&limit=5",
            headers={"Authorization": f"Bearer {test_user['token']}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 5
    
    def test_get_scan_history_chronological_order(self, client: TestClient, test_user: dict, session: Session):
        """Test that scans are ordered by most recent first."""
        import time
        
        # Create scans with slight time differences
        scan_ids = []
        for i in range(3):
            scan = Scan(
                user_id=test_user["user"].id,
                license_text=f"License text {i}",
                status="completed",
                results_json='{"licenses": []}',
                created_at=datetime.utcnow()
            )
            session.add(scan)
            session.commit()
            session.refresh(scan)
            scan_ids.append(scan.id)
            time.sleep(0.01)  # Small delay to ensure different timestamps
        
        response = client.get(
            "/api/scans",
            headers={"Authorization": f"Bearer {test_user['token']}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Most recent scan should be first
        returned_ids = [scan["scan_id"] for scan in data]
        # The order should be reversed (most recent first)
        assert returned_ids == list(reversed(scan_ids))
    
    def test_get_scan_history_without_auth(self, client: TestClient):
        """Test that scan history requires authentication."""
        response = client.get("/api/scans")
        
        assert response.status_code == 403

"""
Tests for authentication API endpoints.

Requirements: 1.1, 1.2, 1.3, 1.4
"""

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


def test_register_success(client: TestClient):
    """Test successful user registration."""
    response = client.post(
        "/api/auth/register",
        json={"username": "testuser", "password": "Test123!"}
    )
    
    assert response.status_code == 201
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert len(data["access_token"]) > 0


def test_register_duplicate_username(client: TestClient):
    """Test registration with duplicate username."""
    # Register first user
    client.post(
        "/api/auth/register",
        json={"username": "testuser", "password": "Test123!"}
    )
    
    # Try to register with same username
    response = client.post(
        "/api/auth/register",
        json={"username": "testuser", "password": "Different123!"}
    )
    
    assert response.status_code == 400
    data = response.json()
    assert "detail" in data
    assert data["detail"]["error"]["code"] == "VALIDATION_ERROR"


def test_register_weak_password(client: TestClient):
    """Test registration with password that doesn't meet complexity requirements."""
    # Too short
    response = client.post(
        "/api/auth/register",
        json={"username": "testuser", "password": "short"}
    )
    
    assert response.status_code == 400
    data = response.json()
    assert "detail" in data
    assert "password" in data["detail"]["error"]["details"]["field"]


def test_register_password_no_diversity(client: TestClient):
    """Test registration with password lacking character diversity."""
    response = client.post(
        "/api/auth/register",
        json={"username": "testuser", "password": "alllowercase"}
    )
    
    assert response.status_code == 400
    data = response.json()
    assert "detail" in data
    assert data["detail"]["error"]["code"] == "VALIDATION_ERROR"


def test_login_success(client: TestClient):
    """Test successful login."""
    # Register user first
    client.post(
        "/api/auth/register",
        json={"username": "testuser", "password": "Test123!"}
    )
    
    # Login
    response = client.post(
        "/api/auth/login",
        json={"username": "testuser", "password": "Test123!"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_login_invalid_username(client: TestClient):
    """Test login with non-existent username."""
    response = client.post(
        "/api/auth/login",
        json={"username": "nonexistent", "password": "Test123!"}
    )
    
    assert response.status_code == 401
    data = response.json()
    assert "detail" in data
    assert data["detail"]["error"]["code"] == "AUTHENTICATION_ERROR"


def test_login_invalid_password(client: TestClient):
    """Test login with incorrect password."""
    # Register user first
    client.post(
        "/api/auth/register",
        json={"username": "testuser", "password": "Test123!"}
    )
    
    # Try to login with wrong password
    response = client.post(
        "/api/auth/login",
        json={"username": "testuser", "password": "WrongPassword123!"}
    )
    
    assert response.status_code == 401
    data = response.json()
    assert "detail" in data
    assert data["detail"]["error"]["code"] == "AUTHENTICATION_ERROR"


def test_protected_endpoint_with_valid_token(client: TestClient):
    """Test accessing a protected endpoint with valid JWT token."""
    # Register and get token
    response = client.post(
        "/api/auth/register",
        json={"username": "testuser", "password": "Test123!"}
    )
    token = response.json()["access_token"]
    
    # Create a simple protected endpoint for testing
    from app.dependencies import CurrentUser
    from fastapi import APIRouter
    
    test_router = APIRouter()
    
    @test_router.get("/test/protected")
    async def protected_route(current_user: CurrentUser):
        return {"user_id": current_user.id, "username": current_user.username}
    
    app.include_router(test_router)
    
    # Access protected endpoint with token
    response = client.get(
        "/test/protected",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "testuser"


def test_protected_endpoint_without_token(client: TestClient):
    """Test accessing a protected endpoint without token."""
    from app.dependencies import CurrentUser
    from fastapi import APIRouter
    
    test_router = APIRouter()
    
    @test_router.get("/test/protected2")
    async def protected_route(current_user: CurrentUser):
        return {"user_id": current_user.id}
    
    app.include_router(test_router)
    
    # Try to access without token
    response = client.get("/test/protected2")
    
    assert response.status_code == 403  # FastAPI returns 403 for missing credentials


def test_protected_endpoint_with_invalid_token(client: TestClient):
    """Test accessing a protected endpoint with invalid token."""
    from app.dependencies import CurrentUser
    from fastapi import APIRouter
    
    test_router = APIRouter()
    
    @test_router.get("/test/protected3")
    async def protected_route(current_user: CurrentUser):
        return {"user_id": current_user.id}
    
    app.include_router(test_router)
    
    # Access with invalid token
    response = client.get(
        "/test/protected3",
        headers={"Authorization": "Bearer invalid_token_here"}
    )
    
    assert response.status_code == 401
    data = response.json()
    assert "detail" in data
    assert data["detail"]["error"]["code"] == "AUTHENTICATION_ERROR"

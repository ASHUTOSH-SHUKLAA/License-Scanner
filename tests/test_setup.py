"""
Basic setup verification tests
"""
import pytest
from fastapi.testclient import TestClient
from main import app


def test_app_exists():
    """Verify the FastAPI app instance exists"""
    assert app is not None
    assert app.title == "License Compliance Scanner API"
    assert app.version == "1.0.0"


def test_root_endpoint():
    """Verify the root endpoint works"""
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "License Compliance Scanner"
    assert data["status"] == "running"
    assert data["version"] == "1.0.0"


def test_health_endpoint():
    """Verify the health check endpoint works"""
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"

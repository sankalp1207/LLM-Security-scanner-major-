"""Test health check and root endpoints."""

from fastapi.testclient import TestClient


def test_root_endpoint(client: TestClient) -> None:
    """Verify root endpoint returns basic project metadata and docs pointer."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "name" in data
    assert "version" in data
    assert data["docs"] == "/docs"
    assert data["status"] == "operational"


def test_health_endpoint(client: TestClient) -> None:
    """Verify /health returns 200 and component statuses."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["environment"] == "testing"
    assert "components" in data
    assert "database" in data["components"]
    assert "ml_classifier" in data["components"]

"""Pytest configuration and shared test fixtures."""

import pytest
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient

from app.config import Settings, get_settings
from app.main import app


@pytest.fixture
def override_settings() -> Settings:
    """Provide test settings overriding database and environments."""
    return Settings(
        ENVIRONMENT="testing",
        DATABASE_URL="sqlite:///:memory:",
        DEMO_RAG_VULNERABLE_MODE=True,
    )


@pytest.fixture
def client(override_settings: Settings) -> TestClient:
    """Synchronous test client fixture."""
    app.dependency_overrides[get_settings] = lambda: override_settings
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
async def async_client(override_settings: Settings):
    """Asynchronous HTTP test client fixture."""
    app.dependency_overrides[get_settings] = lambda: override_settings
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac
    app.dependency_overrides.clear()

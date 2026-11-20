"""Unit tests for scanner components (TargetClient, TestRunner, Orchestrator)."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.connection import Base
from app.scanner.orchestrator import ScanOrchestrator
from app.scanner.target_client import TargetClient
from app.schemas.security import ThreatCategory


@pytest.fixture
def db_session():
    """In-memory SQLite session."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine)
    session = TestingSession()
    try:
        yield session
    finally:
        session.close()


def test_target_validation_local():
    """Verify local loopback destinations pass validation without requiring external flag."""
    val1 = TargetClient.validate_target("http://127.0.0.1:8000/api/v1/demo-rag/query")
    assert val1.is_valid is True
    assert val1.is_local is True

    val2 = TargetClient.validate_target("http://localhost:8000/api/v1/demo-rag/query")
    assert val2.is_valid is True
    assert val2.is_local is True


def test_target_validation_external_authorization():
    """Verify external target is rejected by default unless explicitly authorized."""
    # Without authorization flag
    val_unauth = TargetClient.validate_target("https://api.example.com/llm")
    assert val_unauth.is_valid is False
    assert "explicit authorization" in val_unauth.error_message.lower()

    # With authorization flag
    val_auth = TargetClient.validate_target("https://8.8.8.8/llm", external_authorized=True)
    assert val_auth.is_valid is True
    assert val_auth.is_local is False


def test_target_validation_ssrf_protection():
    """Verify cloud metadata and reserved IPs are blocked even if authorized."""
    val_meta = TargetClient.validate_target(
        "http://169.254.169.254/latest/meta-data/", external_authorized=True
    )
    assert val_meta.is_valid is False
    assert "metadata" in val_meta.error_message.lower()

    val_ftp = TargetClient.validate_target("ftp://127.0.0.1:8000")
    assert val_ftp.is_valid is False
    assert "unsupported scheme" in val_ftp.error_message.lower()

    private = TargetClient.validate_target("http://192.168.1.10/admin", external_authorized=True)
    assert private.is_valid is False
    assert "non-public" in private.error_message.lower()

    embedded_credentials = TargetClient.validate_target("https://user:pass@8.8.8.8/", external_authorized=True)
    assert embedded_credentials.is_valid is False


def test_target_validation_blocks_hostname_resolving_to_private_ip(monkeypatch):
    import socket

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.2.3.4", 443))],
    )
    result = TargetClient.validate_target("https://attacker-controlled.example/", external_authorized=True)
    assert result.is_valid is False
    assert "non-public" in result.error_message.lower()


@pytest.mark.asyncio
async def test_scan_orchestrator_execution(db_session, client):
    """Verify ScanOrchestrator executes against local target and creates findings."""
    from app.database.repository import ScanRepository

    scan = ScanRepository.create_scan(
        db=db_session,
        target_identifier="http://testserver/api/v1/demo-rag/query",
        configuration={"timeout": 5.0},
    )

    orchestrator = ScanOrchestrator(db=db_session)
    completed_scan = await orchestrator.execute_scan(
        scan_id=scan.id,
        target_url="http://testserver/api/v1/demo-rag/query",
        categories=[ThreatCategory.PROMPT_INJECTION],
        max_concurrency=2,
        timeout_seconds=5.0,
        http_client=client,  # TestClient compatible
    )

    assert completed_scan.status in ("COMPLETED", "PARTIALLY_COMPLETED")
    assert completed_scan.summary["total_tests"] > 0
    assert "findings_count" in completed_scan.summary

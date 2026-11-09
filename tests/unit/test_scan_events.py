"""Unit tests for Phase 4 scan event system, sequence monotonicity, pub-sub, and sanitization."""

import asyncio
from datetime import datetime, timezone
import pytest
from sqlalchemy.orm import Session

from app.database.connection import SessionLocal
from app.database.models import Project, Scan, TargetConfiguration
from app.database.repository import (
    ProjectRepository,
    ScanEventRepository,
    ScanRepository,
    TargetConfigurationRepository,
)
from app.schemas.events import ScanEventType
from app.services.event_service import ScanEventService, sanitize_payload


@pytest.fixture
def db_session():
    """Isolated database session fixture for event tests."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_payload_sanitization():
    """Verify recursive redaction of sensitive credentials and secrets in event payloads."""
    sensitive_payload = {
        "target_url": "http://127.0.0.1:8000/api/v1/demo-rag/query",
        "api_key": "sk-secret-live-12345",
        "nested": {
            "auth_token": "Bearer secret_jwt_payload",
            "password": "super-secret-password",
            "safe_metric": 42,
        },
        "list_items": [
            {"Authorization": "Bearer token123", "name": "header1"},
            {"public_info": "visible"},
        ],
    }

    sanitized = sanitize_payload(sensitive_payload)

    # Sensitive values must be redacted
    assert sanitized["api_key"] == "[REDACTED]"
    assert sanitized["nested"]["auth_token"] == "[REDACTED]"
    assert sanitized["nested"]["password"] == "[REDACTED]"
    assert sanitized["list_items"][0]["Authorization"] == "[REDACTED]"

    # Non-sensitive values must be preserved unmodified
    assert sanitized["target_url"] == "http://127.0.0.1:8000/api/v1/demo-rag/query"
    assert sanitized["nested"]["safe_metric"] == 42
    assert sanitized["list_items"][0]["name"] == "header1"
    assert sanitized["list_items"][1]["public_info"] == "visible"


def test_scan_event_persistence_and_sequence(db_session: Session):
    """Verify monotonic sequence increments and database persistence via ScanEventRepository."""
    # Create test scan
    scan = ScanRepository.create_scan(
        db=db_session,
        target_identifier="http://127.0.0.1:8000/test",
        configuration={"preset": "quick_scan"},
        status="RUNNING",
    )
    scan_id = scan.id

    try:
        # Publish multiple sequential events
        ev1 = ScanEventService.publish_event(
            scan_id=scan_id,
            event_type=ScanEventType.SCAN_STARTED.value,
            payload={"preset": "quick_scan", "total_tests": 10},
            db=db_session,
        )
        ev2 = ScanEventService.publish_event(
            scan_id=scan_id,
            event_type=ScanEventType.TEST_STARTED.value,
            payload={"test_case_id": "test_01", "category": "prompt_injection"},
            db=db_session,
        )
        ev3 = ScanEventService.publish_event(
            scan_id=scan_id,
            event_type=ScanEventType.TEST_COMPLETED.value,
            payload={"test_case_id": "test_01", "status": "PASSED"},
            db=db_session,
        )

        # Monotonicity check
        assert ev1.sequence < ev2.sequence < ev3.sequence
        assert ev1.sequence >= 1
        assert ev2.sequence == ev1.sequence + 1
        assert ev3.sequence == ev2.sequence + 1

        # Database query verification
        events = ScanEventRepository.list_events_by_scan(db=db_session, scan_id=scan_id, since_seq=0)
        assert len(events) >= 3
        seqs = [e.sequence for e in events]
        assert seqs == sorted(seqs)

        # Cursor pagination via since_seq
        events_after_1 = ScanEventRepository.list_events_by_scan(
            db=db_session, scan_id=scan_id, since_seq=ev1.sequence
        )
        assert len(events_after_1) >= 2
        assert all(e.sequence > ev1.sequence for e in events_after_1)

        # Max sequence lookup
        latest_seq = ScanEventRepository.get_latest_sequence(db=db_session, scan_id=scan_id)
        assert latest_seq == ev3.sequence

    finally:
        ScanRepository.delete_scan(db_session, scan_id)


def test_progress_snapshot_calculation(db_session: Session):
    """Verify accurate progress percentage and KPI derivation from backend state."""
    scan = ScanRepository.create_scan(
        db=db_session,
        target_identifier="http://127.0.0.1:8000/test",
        configuration={"preset": "quick_scan"},
        status="RUNNING",
        total_tests=20,
    )
    scan_id = scan.id

    try:
        # Initial snapshot (0/20)
        snapshot = ScanEventService.get_progress_snapshot(db_session, scan_id)
        assert snapshot.scan_id == scan_id
        assert snapshot.total_tests == 20
        assert snapshot.completed_tests == 0
        assert snapshot.progress_percentage == 0.0

        # Update test metrics: 10 completed, 8 passed, 2 failed
        ScanRepository.update_scan_status(
            db=db_session,
            scan_id=scan_id,
            status="RUNNING",
            completed_tests=10,
            passed_tests=8,
            failed_tests=2,
            inconclusive_tests=0,
            execution_errors=0,
        )

        snapshot_half = ScanEventService.get_progress_snapshot(db_session, scan_id)
        assert snapshot_half.completed_tests == 10
        assert snapshot_half.passed_tests == 8
        assert snapshot_half.failed_tests == 2
        assert snapshot_half.progress_percentage == 50.0

        # Complete scan (20/20)
        ScanRepository.update_scan_status(
            db=db_session,
            scan_id=scan_id,
            status="COMPLETED",
            completed_tests=20,
            passed_tests=18,
            failed_tests=2,
        )

        snapshot_done = ScanEventService.get_progress_snapshot(db_session, scan_id)
        assert snapshot_done.status == "COMPLETED"
        assert snapshot_done.progress_percentage == 100.0

    finally:
        ScanRepository.delete_scan(db_session, scan_id)


@pytest.mark.asyncio
async def test_pub_sub_broadcasting(db_session: Session):
    """Verify live subscriber queue delivery and SSE message formatting."""
    scan = ScanRepository.create_scan(
        db=db_session,
        target_identifier="http://127.0.0.1:8000/test",
        configuration={"preset": "quick_scan"},
        status="RUNNING",
    )
    scan_id = scan.id

    try:
        q = asyncio.Queue()
        ScanEventService._subscribers[scan_id].add(q)

        # Publish event
        ev = ScanEventService.publish_event(
            scan_id=scan_id,
            event_type=ScanEventType.TEST_COMPLETED.value,
            payload={"test_case_id": "test_broadcast_01", "status": "PASSED"},
            db=db_session,
        )

        # Subscriber queue should receive event
        received = await asyncio.wait_for(q.get(), timeout=2.0)
        assert received.event_id == ev.event_id
        assert received.sequence == ev.sequence
        assert received.event_type == ScanEventType.TEST_COMPLETED.value

        # SSE formatting check
        sse_text = ScanEventService.format_sse(received)
        assert f"id: {received.sequence}\n" in sse_text
        assert f"event: {ScanEventType.TEST_COMPLETED.value}\n" in sse_text
        assert "data: {" in sse_text

    finally:
        ScanEventService._subscribers[scan_id].discard(q)
        ScanRepository.delete_scan(db_session, scan_id)

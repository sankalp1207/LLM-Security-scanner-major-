"""Integration tests for Phase 4 real-time scan monitoring API, SSE endpoints, and execution telemetry."""

import uuid
import pytest
from fastapi.testclient import TestClient

from app.database.connection import SessionLocal
from app.database.repository import ProjectRepository, ScanRepository
from app.main import app
from app.schemas.events import ScanEventType


@pytest.fixture
def client():
    """FastAPI test client fixture."""
    with TestClient(app) as test_client:
        yield test_client


def test_scan_progress_api_endpoints(client: TestClient):
    """Test GET /api/v1/scans/{scan_id}/progress endpoint contract and ownership rules."""
    headers_a = {"X-User-Id": f"user_progress_a_{uuid.uuid4().hex[:6]}"}
    headers_b = {"X-User-Id": f"user_progress_b_{uuid.uuid4().hex[:6]}"}

    # 1. Create project for user A
    proj_res = client.post(
        "/api/v1/projects",
        json={
            "name": f"Progress Test Project {uuid.uuid4().hex[:6]}",
            "application_type": "rag",
            "environment": "development",
            "target_type": "demo",
            "target_configuration": {
                "provider": "demo",
                "endpoint_url": "http://testserver/api/v1/demo-rag/query",
            },
        },
        headers=headers_a,
    )
    assert proj_res.status_code == 200
    project_id = proj_res.json()["id"]

    try:
        # 2. Initiate quick scan
        scan_res = client.post(
            f"/api/v1/projects/{project_id}/scans",
            json={"preset": "quick_scan", "custom_max_tests": 2, "sync_execute": True},
            headers=headers_a,
        )
        assert scan_res.status_code == 200
        scan_id = scan_res.json()["id"]

        # 3. Retrieve progress as user A
        prog_res = client.get(f"/api/v1/scans/{scan_id}/progress", headers=headers_a)
        assert prog_res.status_code == 200
        prog = prog_res.json()
        assert prog["scan_id"] == scan_id
        assert prog["status"] == "COMPLETED"
        assert prog["progress_percentage"] == 100.0
        assert prog["completed_tests"] > 0
        assert prog["total_tests"] >= prog["completed_tests"]
        assert "elapsed_seconds" in prog
        assert "latest_sequence" in prog
        assert prog["latest_sequence"] >= 1

        # 4. User B should receive 403 for unauthorized project scan progress
        prog_b_res = client.get(f"/api/v1/scans/{scan_id}/progress", headers=headers_b)
        assert prog_b_res.status_code == 403

        # 5. Non-existent scan should return 404
        prog_404 = client.get("/api/v1/scans/non-existent-scan-id/progress", headers=headers_a)
        assert prog_404.status_code == 404

    finally:
        client.delete(f"/api/v1/projects/{project_id}", headers=headers_a)


def test_scan_events_cursor_and_replay_api(client: TestClient):
    """Test GET /api/v1/scans/{scan_id}/events cursor replay and monotonic sequencing."""
    headers = {"X-User-Id": f"user_events_test_{uuid.uuid4().hex[:6]}"}

    # Create project and run scan
    proj_res = client.post(
        "/api/v1/projects",
        json={
            "name": f"Events Replay Project {uuid.uuid4().hex[:6]}",
            "application_type": "rag",
            "environment": "development",
            "target_type": "demo",
            "target_configuration": {
                "provider": "demo",
                "endpoint_url": "http://testserver/api/v1/demo-rag/query",
            },
        },
        headers=headers,
    )
    assert proj_res.status_code == 200
    project_id = proj_res.json()["id"]

    try:
        scan_res = client.post(
            f"/api/v1/projects/{project_id}/scans",
            json={"preset": "quick_scan", "custom_max_tests": 3, "sync_execute": True},
            headers=headers,
        )
        assert scan_res.status_code == 200
        scan_id = scan_res.json()["id"]

        # Fetch all events (since_seq=0)
        events_res = client.get(f"/api/v1/scans/{scan_id}/events", headers=headers)
        assert events_res.status_code == 200
        data = events_res.json()
        assert data["scan_id"] == scan_id
        assert data["total_events"] >= 5
        events = data["events"]
        assert len(events) >= 5

        # Verify strict sequence monotonicity
        sequences = [e["sequence"] for e in events]
        assert sequences == sorted(sequences)
        assert len(set(sequences)) == len(sequences)  # All sequences unique

        # Verify presence of core event types
        event_types = {e["event_type"] for e in events}
        assert ScanEventType.SCAN_CREATED.value in event_types
        assert ScanEventType.SCAN_QUEUED.value in event_types
        assert ScanEventType.TARGET_VERIFIED.value in event_types
        assert ScanEventType.SCAN_STARTED.value in event_types
        assert ScanEventType.TEST_STARTED.value in event_types
        assert ScanEventType.SCAN_PROGRESS.value in event_types
        assert ScanEventType.SCAN_COMPLETED.value in event_types

        # Reconnection cursor test: fetch since_seq = midway
        mid_seq = sequences[len(sequences) // 2]
        replay_res = client.get(f"/api/v1/scans/{scan_id}/events?since_seq={mid_seq}", headers=headers)
        assert replay_res.status_code == 200
        replay_events = replay_res.json()["events"]
        assert all(e["sequence"] > mid_seq for e in replay_events)
        assert len(replay_events) == len([s for s in sequences if s > mid_seq])

        # Filter by specific event type
        progress_res = client.get(
            f"/api/v1/scans/{scan_id}/events?event_type={ScanEventType.SCAN_PROGRESS.value}",
            headers=headers,
        )
        assert progress_res.status_code == 200
        prog_events = progress_res.json()["events"]
        assert all(e["event_type"] == ScanEventType.SCAN_PROGRESS.value for e in prog_events)

    finally:
        client.delete(f"/api/v1/projects/{project_id}", headers=headers)


def test_sse_live_streaming_endpoint(client: TestClient):
    """Test GET /api/v1/scans/{scan_id}/live SSE headers and historical replay formatting."""
    headers = {"X-User-Id": f"user_sse_test_{uuid.uuid4().hex[:6]}"}

    proj_res = client.post(
        "/api/v1/projects",
        json={
            "name": f"SSE Test Project {uuid.uuid4().hex[:6]}",
            "application_type": "rag",
            "environment": "development",
            "target_type": "demo",
            "target_configuration": {
                "provider": "demo",
                "endpoint_url": "http://testserver/api/v1/demo-rag/query",
            },
        },
        headers=headers,
    )
    assert proj_res.status_code == 200
    project_id = proj_res.json()["id"]

    try:
        scan_res = client.post(
            f"/api/v1/projects/{project_id}/scans",
            json={"preset": "quick_scan", "custom_max_tests": 2, "sync_execute": True},
            headers=headers,
        )
        assert scan_res.status_code == 200
        scan_id = scan_res.json()["id"]

        # Call SSE endpoint with streaming request
        with client.stream("GET", f"/api/v1/scans/{scan_id}/live?since_seq=0", headers=headers) as response:
            assert response.status_code == 200
            assert "text/event-stream" in response.headers.get("content-type", "")

            # Read first few lines of the stream
            lines = []
            for line in response.iter_lines():
                if line:
                    lines.append(line)
                if len(lines) >= 6:
                    break

            # Verify SSE protocol format
            full_text = "\n".join(lines)
            assert "id:" in full_text
            assert "event:" in full_text
            assert "data:" in full_text

    finally:
        client.delete(f"/api/v1/projects/{project_id}", headers=headers)


def test_scan_cancellation_emits_event(client: TestClient):
    """Verify cancelling an active scan records SCAN_CANCELLED event."""
    user_id = f"user_cancel_evt_{uuid.uuid4().hex[:6]}"
    headers = {"X-User-Id": user_id}

    # Create dummy queued scan in DB
    db = SessionLocal()
    try:
        scan = ScanRepository.create_scan(
            db=db,
            target_identifier="http://127.0.0.1:8000/test",
            configuration={"preset": "quick_scan"},
            status="QUEUED",
            user_id=user_id,
        )
        scan_id = scan.id
    finally:
        db.close()

    try:
        # Cancel scan via API
        cancel_res = client.post(
            f"/api/v1/scans/{scan_id}/cancel",
            json={"reason": "Aborted by security engineer"},
            headers=headers,
        )
        assert cancel_res.status_code == 200
        assert cancel_res.json()["status"] == "CANCELLED"
        assert cancel_res.json()["cancellation_reason"] == "Aborted by security engineer"

        # Verify SCAN_CANCELLED event exists
        events_res = client.get(f"/api/v1/scans/{scan_id}/events", headers=headers)
        assert events_res.status_code == 200
        event_types = [e["event_type"] for e in events_res.json()["events"]]
        assert ScanEventType.SCAN_CANCELLED.value in event_types

        # Verify progress snapshot reflects cancellation
        prog_res = client.get(f"/api/v1/scans/{scan_id}/progress", headers=headers)
        assert prog_res.status_code == 200
        assert prog_res.json()["status"] == "CANCELLED"
        assert prog_res.json()["cancellation_reason"] == "Aborted by security engineer"

    finally:
        db = SessionLocal()
        try:
            ScanRepository.delete_scan(db, scan_id)
        finally:
            db.close()

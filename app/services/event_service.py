"""Real-time scan event broadcasting, sequence coordination, SSE streaming, and payload sanitization."""

import asyncio
from collections import defaultdict
from datetime import datetime, timezone
import json
import logging
import re
from typing import Any, AsyncGenerator, Dict, List, Optional, Set
import uuid

from sqlalchemy.orm import Session

from app.database.connection import SessionLocal
from app.database.models import Scan
from app.database.repository import FindingRepository, ScanEventRepository, ScanRepository
from app.schemas.events import (
    ScanEventListResponse,
    ScanEventSchema,
    ScanEventType,
    ScanProgressResponse,
)

logger = logging.getLogger("event_service")

# Regex pattern matching sensitive keys that should be redacted from broadcasted event payloads
SENSITIVE_KEY_PATTERN = re.compile(
    r"(api_?key|token|secret|password|authorization|auth_?header|credential|private_?key)",
    re.IGNORECASE,
)


def sanitize_payload(obj: Any) -> Any:
    """Recursively redact sensitive keys from dictionary and list payloads."""
    if isinstance(obj, dict):
        sanitized = {}
        for k, v in obj.items():
            if SENSITIVE_KEY_PATTERN.search(str(k)):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = sanitize_payload(v)
        return sanitized
    elif isinstance(obj, list):
        return [sanitize_payload(item) for item in obj]
    return obj


class ScanEventService:
    """
    Central event dispatcher coordinating live SSE broadcasting, sequence monotonicity,
    database event audit logs, and progress state snapshots.
    """

    # In-memory subscriber queues per scan ID
    _subscribers: Dict[str, Set[asyncio.Queue]] = defaultdict(set)
    # Monotonic sequence counter per scan ID
    _sequence_counters: Dict[str, int] = defaultdict(int)
    # Active runtime metadata (e.g., current category, current test id)
    _runtime_metadata: Dict[str, Dict[str, Any]] = defaultdict(dict)
    _lock = asyncio.Lock()

    @classmethod
    def _get_next_sequence(cls, scan_id: str, db: Optional[Session] = None) -> int:
        """Get the next sequence number for a scan, initializing from DB if needed."""
        if scan_id not in cls._sequence_counters:
            latest_seq = 0
            if db:
                latest_seq = ScanEventRepository.get_latest_sequence(db, scan_id)
            else:
                session = SessionLocal()
                try:
                    latest_seq = ScanEventRepository.get_latest_sequence(session, scan_id)
                finally:
                    session.close()
            cls._sequence_counters[scan_id] = latest_seq

        cls._sequence_counters[scan_id] += 1
        return cls._sequence_counters[scan_id]

    @classmethod
    def publish_event(
        cls,
        scan_id: str,
        event_type: str,
        payload: Optional[Dict[str, Any]] = None,
        db: Optional[Session] = None,
        persist: bool = True,
        version: str = "1.0",
    ) -> ScanEventSchema:
        """
        Publish a structured scan event.
        - Assigns monotonic sequence number.
        - Sanitizes payload to protect credentials and secrets.
        - Persists event to SQLite/PostgreSQL audit trail.
        - Dispatches event to all active SSE subscriber queues.
        """
        raw_payload = payload or {}
        sanitized = sanitize_payload(raw_payload)

        # Update in-memory runtime telemetry if provided
        if "current_category" in sanitized:
            cls._runtime_metadata[scan_id]["current_category"] = sanitized["current_category"]
        if "current_test_id" in sanitized:
            cls._runtime_metadata[scan_id]["current_test_id"] = sanitized["current_test_id"]

        seq = cls._get_next_sequence(scan_id, db=db)
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        # Persist event in database
        if persist:
            def _persist(session: Session):
                ScanEventRepository.create_event(
                    db=session,
                    scan_id=scan_id,
                    event_type=event_type,
                    sequence=seq,
                    payload=sanitized,
                    version=version,
                    event_id=event_id,
                )

            if db:
                _persist(db)
            else:
                session = SessionLocal()
                try:
                    _persist(session)
                finally:
                    session.close()

        event_schema = ScanEventSchema(
            event_id=event_id,
            scan_id=scan_id,
            event_type=event_type,
            sequence=seq,
            timestamp=timestamp,
            payload=sanitized,
            version=version,
        )

        # Broadcast to active subscriber queues
        queues = cls._subscribers.get(scan_id, set())
        for q in list(queues):
            try:
                q.put_nowait(event_schema)
            except Exception as e:
                logger.warning(f"Failed to deliver event to subscriber queue: {e}")

        return event_schema

    @classmethod
    async def subscribe(
        cls,
        scan_id: str,
        since_seq: int = 0,
        heartbeat_interval: float = 15.0,
    ) -> AsyncGenerator[str, None]:
        """
        Async generator yielding SSE-formatted events for a scan.
        Supports replay of missed events since `since_seq` on reconnection,
        followed by real-time stream updates and periodic keepalives.
        """
        q: asyncio.Queue = asyncio.Queue()
        cls._subscribers[scan_id].add(q)

        terminal_events = {
            ScanEventType.SCAN_COMPLETED.value,
            ScanEventType.SCAN_CANCELLED.value,
            ScanEventType.SCAN_PARTIALLY_COMPLETED.value,
            ScanEventType.SCAN_ERROR.value,
        }

        try:
            # 1. Replay missed historical events from database
            session = SessionLocal()
            has_terminal_event = False
            try:
                historical_events = ScanEventRepository.list_events_by_scan(
                    db=session,
                    scan_id=scan_id,
                    since_seq=since_seq,
                    limit=500,
                )
                for h_ev in historical_events:
                    ev_schema = ScanEventSchema(
                        event_id=h_ev.id,
                        scan_id=h_ev.scan_id,
                        event_type=h_ev.event_type,
                        sequence=h_ev.sequence,
                        timestamp=h_ev.created_at.isoformat(),
                        payload=h_ev.payload,
                        version=h_ev.version,
                    )
                    yield cls.format_sse(ev_schema)
                    if h_ev.event_type in terminal_events:
                        has_terminal_event = True

                # Also check if scan has completed
                if not has_terminal_event:
                    cur_scan = ScanRepository.get_scan(session, scan_id)
                    if cur_scan and cur_scan.status in ("COMPLETED", "FAILED", "CANCELLED", "PARTIALLY_COMPLETED"):
                        has_terminal_event = True
            finally:
                session.close()

            # If the scan was already in a terminal state, terminate stream gracefully
            if has_terminal_event:
                return

            # 2. Stream live events as they arrive
            while True:
                try:
                    event: ScanEventSchema = await asyncio.wait_for(q.get(), timeout=heartbeat_interval)
                    # If this event was already delivered in historical replay, skip
                    if event.sequence <= since_seq:
                        continue
                    yield cls.format_sse(event)

                    if event.event_type in terminal_events:
                        logger.info(f"Scan {scan_id} reached terminal event {event.event_type}; ending SSE stream.")
                        break
                except asyncio.TimeoutError:
                    # Send periodic SSE keepalive comment to prevent proxy timeouts
                    yield ": keepalive\n\n"
        finally:
            cls._subscribers[scan_id].discard(q)
            if not cls._subscribers[scan_id]:
                cls._subscribers.pop(scan_id, None)

    @staticmethod
    def format_sse(event: ScanEventSchema) -> str:
        """Format a ScanEventSchema instance into standard Server-Sent Event text."""
        data_json = json.dumps(event.model_dump())
        return f"id: {event.sequence}\nevent: {event.event_type}\ndata: {data_json}\n\n"

    @classmethod
    def get_progress_snapshot(cls, db: Session, scan_id: str) -> ScanProgressResponse:
        """
        Calculate and return a consistent real-time progress snapshot
        derived directly from database records and in-memory runtime telemetry.
        """
        scan = ScanRepository.get_scan(db, scan_id)
        if not scan:
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")

        total = scan.total_tests or 0
        completed = scan.completed_tests or 0
        passed = scan.passed_tests or 0
        failed = scan.failed_tests or 0
        inconclusive = scan.inconclusive_tests or 0
        skipped = scan.skipped_tests or 0
        errors = scan.execution_errors or 0

        # Calculate accurate completion percentage based on backend execution
        if scan.status in ("COMPLETED", "PARTIALLY_COMPLETED"):
            progress_pct = 100.0
        elif scan.status in ("CANCELLED", "FAILED") and total == 0:
            progress_pct = 0.0
        elif total > 0:
            progress_pct = round(min(100.0, (completed / total) * 100.0), 1)
        else:
            progress_pct = 0.0

        findings = FindingRepository.list_findings_by_scan(db, scan_id)
        severity_dist = FindingRepository.get_severity_distribution(db, scan_id)

        # Elapsed time
        now = datetime.now(timezone.utc)
        start_ts = scan.start_timestamp
        if start_ts.tzinfo is None:
            start_ts = start_ts.replace(tzinfo=timezone.utc)

        if scan.completion_timestamp:
            end_ts = scan.completion_timestamp
            if end_ts.tzinfo is None:
                end_ts = end_ts.replace(tzinfo=timezone.utc)
            elapsed = max(0.0, (end_ts - start_ts).total_seconds())
        else:
            elapsed = max(0.0, (now - start_ts).total_seconds())

        latest_seq = ScanEventRepository.get_latest_sequence(db, scan_id)
        runtime = cls._runtime_metadata.get(scan_id, {})

        # Build category breakdown if summary contains it or from test executions
        category_progress: Dict[str, Dict[str, int]] = {}
        if scan.summary and "category_breakdown" in scan.summary:
            for cat, count in scan.summary.get("category_breakdown", {}).items():
                category_progress[cat] = {"findings": count}

        return ScanProgressResponse(
            scan_id=scan.id,
            project_id=scan.project_id,
            preset=scan.preset,
            status=scan.status,
            progress_percentage=progress_pct,
            total_tests=total,
            completed_tests=completed,
            passed_tests=passed,
            failed_tests=failed,
            inconclusive_tests=inconclusive,
            skipped_tests=skipped,
            execution_errors=errors,
            findings_count=len(findings),
            current_category=runtime.get("current_category"),
            current_test_id=runtime.get("current_test_id"),
            latest_sequence=latest_seq,
            elapsed_seconds=round(elapsed, 1),
            cancellation_reason=scan.cancellation_reason,
            failure_reason=scan.failure_reason,
            severity_breakdown=severity_dist,
            category_progress=category_progress,
        )

    @classmethod
    def get_events_for_scan(
        cls,
        db: Session,
        scan_id: str,
        since_seq: int = 0,
        limit: int = 100,
        event_type: Optional[str] = None,
    ) -> ScanEventListResponse:
        """Fetch historical events with cursor pagination."""
        events = ScanEventRepository.list_events_by_scan(
            db=db,
            scan_id=scan_id,
            since_seq=since_seq,
            limit=limit,
            event_type=event_type,
        )
        total_events = ScanEventRepository.count_events(db, scan_id)
        latest_seq = ScanEventRepository.get_latest_sequence(db, scan_id)

        items = [
            ScanEventSchema(
                event_id=e.id,
                scan_id=e.scan_id,
                event_type=e.event_type,
                sequence=e.sequence,
                timestamp=e.created_at.isoformat(),
                payload=e.payload,
                version=e.version,
            )
            for e in events
        ]
        return ScanEventListResponse(
            scan_id=scan_id,
            total_events=total_events,
            latest_sequence=latest_seq,
            events=items,
        )

"""Schemas for real-time security scan events, streaming telemetry, and progress tracking."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ScanEventType(str, Enum):
    """Structured event types emitted during scan lifecycle and execution."""

    SCAN_CREATED = "SCAN_CREATED"
    SCAN_QUEUED = "SCAN_QUEUED"
    SCAN_STARTED = "SCAN_STARTED"
    TARGET_VERIFIED = "TARGET_VERIFIED"
    TEST_STARTED = "TEST_STARTED"
    TEST_COMPLETED = "TEST_COMPLETED"
    TEST_FAILED = "TEST_FAILED"
    FINDING_CREATED = "FINDING_CREATED"
    CATEGORY_COMPLETED = "CATEGORY_COMPLETED"
    SCAN_PROGRESS = "SCAN_PROGRESS"
    SCAN_WARNING = "SCAN_WARNING"
    SCAN_ERROR = "SCAN_ERROR"
    SCAN_CANCELLED = "SCAN_CANCELLED"
    SCAN_COMPLETED = "SCAN_COMPLETED"
    SCAN_PARTIALLY_COMPLETED = "SCAN_PARTIALLY_COMPLETED"


class ScanEventSchema(BaseModel):
    """Structured telemetry event payload for live monitoring and reconnection recovery."""

    event_id: str = Field(description="Unique event UUID")
    scan_id: str = Field(description="ID of the scan being monitored")
    event_type: str = Field(description="Canonical event type name")
    sequence: int = Field(ge=1, description="Monotonically increasing sequence number per scan")
    timestamp: str = Field(description="ISO 8601 UTC timestamp when the event occurred")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Sanitized event data and telemetry")
    version: str = Field(default="1.0", description="Event schema specification version")

    model_config = {"from_attributes": True}


class ScanEventListResponse(BaseModel):
    """Paginated or cursor-based list of scan events for reconnection replay."""

    scan_id: str
    total_events: int
    latest_sequence: int
    events: List[ScanEventSchema]


class CategoryProgressItem(BaseModel):
    """Category-level execution counts."""

    category: str
    total: int = 0
    completed: int = 0
    passed: int = 0
    failed: int = 0
    inconclusive: int = 0
    errors: int = 0


class ScanProgressResponse(BaseModel):
    """Real-time progress snapshot for polling fallback and status dashboards."""

    scan_id: str
    project_id: Optional[str] = None
    preset: Optional[str] = "quick_scan"
    status: str
    progress_percentage: float = Field(ge=0.0, le=100.0, description="Percentage of execution completed")
    total_tests: int = 0
    completed_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    inconclusive_tests: int = 0
    skipped_tests: int = 0
    execution_errors: int = 0
    findings_count: int = 0
    current_category: Optional[str] = None
    current_test_id: Optional[str] = None
    latest_sequence: int = 0
    elapsed_seconds: float = 0.0
    cancellation_reason: Optional[str] = None
    failure_reason: Optional[str] = None
    severity_breakdown: Dict[str, int] = Field(default_factory=dict)
    category_progress: Dict[str, Dict[str, int]] = Field(default_factory=dict)

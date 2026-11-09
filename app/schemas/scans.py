"""Schemas for security scans, presets, test executions, and vulnerability findings."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.schemas.security import ThreatCategory


class ScanStatus(str, Enum):
    """Execution lifecycle states of a scan."""

    CREATED = "CREATED"
    QUEUED = "QUEUED"
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIALLY_COMPLETED = "PARTIALLY_COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ScanCreateRequest(BaseModel):
    """Legacy or direct payload to initiate a new security scan."""

    target_url: str = Field(
        default="http://127.0.0.1:8000/api/v1/demo-rag/query",
        description="Target endpoint URL (default is local demo RAG)",
    )
    categories: Optional[List[ThreatCategory]] = Field(
        default=None,
        description="List of threat categories to test (default is all)",
    )
    max_concurrency: int = Field(default=5, ge=1, le=10, description="Bounded concurrency for test execution")
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=60.0, description="Per-request timeout in seconds")
    external_target_authorized: bool = Field(
        default=False,
        description="Explicit acknowledgement of authorization when scanning non-local targets",
    )
    enable_mutation_fuzzing: bool = Field(
        default=False,
        description="Generate adversarial mutated test cases (Base64, Leetspeak, Homoglyph, Delimiter, etc.)",
    )
    mutation_types: Optional[List[str]] = Field(
        default=None,
        description="List of mutation strategies to apply (default all available)",
    )


class ProjectScanCreateRequest(BaseModel):
    """Payload to initiate a one-click security scan scoped to an enterprise project."""

    preset: str = Field(
        default="quick_scan",
        description="Preset mode: quick_scan, full_scan, or deep_red_team",
    )
    categories: Optional[List[str]] = Field(
        default=None,
        description="Optional explicit categories to test. Defaults to preset configuration.",
    )
    custom_max_tests: Optional[int] = Field(
        default=None,
        ge=1,
        le=200,
        description="Optional ceiling overriding preset max test count.",
    )
    custom_concurrency: Optional[int] = Field(
        default=None,
        ge=1,
        le=10,
        description="Optional override for concurrent connection limit.",
    )
    custom_timeout_seconds: Optional[float] = Field(
        default=None,
        ge=1.0,
        le=60.0,
        description="Optional override for per-request timeout.",
    )
    enable_mutation_fuzzing: Optional[bool] = Field(
        default=None,
        description="Override mutation fuzzing setting (default derived from preset).",
    )
    mutation_types: Optional[List[str]] = Field(
        default=None,
        description="List of mutation strategies if fuzzing is active.",
    )
    external_target_authorized: bool = Field(
        default=False,
        description="Explicit user acknowledgement of authorization when targeting external endpoints.",
    )
    sync_execute: bool = Field(
        default=False,
        description="Whether to execute synchronously before returning response (useful for test suites).",
    )


class ScanCancelRequest(BaseModel):
    """Payload requesting safe cancellation of an active or queued scan."""

    reason: Optional[str] = Field(
        default="Cancelled by user",
        max_length=255,
        description="Reason for terminating the scan prematurely",
    )


class FindingResponse(BaseModel):
    """Response schema for a single finding."""

    id: str
    scan_id: str
    category: str
    severity: str
    title: str
    description: str
    evidence: Dict[str, Any]
    confidence_score: Optional[float] = None
    target_component: str
    affected_test_case: str
    detection_method: str
    remediation: str
    creation_timestamp: str
    retest_status: str

    model_config = {"from_attributes": True}


class TestExecutionResponse(BaseModel):
    """Response schema for an individual security test execution and observed telemetry."""

    id: str
    scan_id: str
    test_case_id: str
    category: str
    test_version: str
    input_fixture: str
    expected_behavior: str
    observed_behavior: str
    execution_status: str
    latency_ms: float
    response_status: Optional[int] = None
    detection_result: Dict[str, Any] = Field(default_factory=dict)
    evidence: Dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None

    model_config = {"from_attributes": True}


class TestExecutionListResponse(BaseModel):
    """Paginated list of test execution records."""

    total: int
    items: List[TestExecutionResponse]


class ScanResponse(BaseModel):
    """Response schema for scan execution summary and metadata."""

    id: str
    project_id: Optional[str] = None
    user_id: Optional[str] = "default_user"
    preset: Optional[str] = "quick_scan"
    target_identifier: str
    status: str
    configuration: Dict[str, Any]
    configuration_snapshot: Optional[Dict[str, Any]] = None
    start_timestamp: str
    completion_timestamp: Optional[str] = None
    summary: Dict[str, Any] = Field(default_factory=dict)
    scanner_version: str = "1.0.0"
    findings_count: Optional[int] = 0

    # Test count metrics
    total_tests: Optional[int] = 0
    completed_tests: Optional[int] = 0
    passed_tests: Optional[int] = 0
    failed_tests: Optional[int] = 0
    inconclusive_tests: Optional[int] = 0
    skipped_tests: Optional[int] = 0
    execution_errors: Optional[int] = 0

    # Lifecycle diagnostics
    cancellation_reason: Optional[str] = None
    failure_reason: Optional[str] = None

    model_config = {"from_attributes": True}


class ScanListResponse(BaseModel):
    """Paginated list of scans."""

    total: int
    items: List[ScanResponse]

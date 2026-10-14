"""Schemas for security scans and vulnerability findings."""

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from app.schemas.security import ThreatCategory


class ScanStatus(str, Enum):
    """Execution lifecycle states of a scan."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    PARTIALLY_COMPLETED = "PARTIALLY_COMPLETED"
    CANCELLED = "CANCELLED"


class ScanCreateRequest(BaseModel):
    """Payload to initiate a new security scan."""

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


class ScanResponse(BaseModel):
    """Response schema for scan execution summary and metadata."""

    id: str
    target_identifier: str
    status: ScanStatus
    configuration: Dict[str, Any]
    start_timestamp: str
    completion_timestamp: Optional[str] = None
    summary: Dict[str, Any] = Field(default_factory=dict)
    scanner_version: str = "1.0.0"
    findings_count: Optional[int] = 0

    model_config = {"from_attributes": True}


class ScanListResponse(BaseModel):
    """Paginated list of scans."""

    total: int
    items: List[ScanResponse]

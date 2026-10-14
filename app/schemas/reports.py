"""Schemas for generated security audit reports."""

from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from app.schemas.scans import FindingResponse


class ScanReportResponse(BaseModel):
    """Structured report schema returned by GET /api/v1/scans/{scan_id}/report."""

    scan_id: str
    target_identifier: str
    scanner_version: str = "1.0.0"
    model_version: str = "1.0.0"
    status: str
    start_time: str
    completion_time: Optional[str] = None
    total_tests: int = 0
    tests_passed: int = 0
    tests_failed: int = 0
    tests_skipped: int = 0
    execution_errors: int = 0
    findings_by_severity: Dict[str, int] = Field(default_factory=dict)
    findings_by_category: Dict[str, int] = Field(default_factory=dict)
    findings: List[FindingResponse] = Field(default_factory=list)
    remediation_recommendations: List[Dict[str, str]] = Field(default_factory=list)
    evaluation_limitations: List[str] = Field(default_factory=list)
    summary: str = ""

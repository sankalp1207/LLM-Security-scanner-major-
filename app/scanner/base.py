"""Base classes and data models for security scanner execution."""

from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class TargetValidationResult(BaseModel):
    """Validation report for a configured target endpoint."""

    is_valid: bool
    target_url: str
    host: str
    is_local: bool
    error_message: Optional[str] = None


class ExecutionResult(BaseModel):
    """Captured telemetry and payload from a single security test execution."""

    test_case_id: str
    category: str
    input_text: str
    response_status: Optional[int] = None
    response_text: Optional[str] = None
    retrieved_documents: list[Dict[str, Any]] = Field(default_factory=list)
    latency_ms: float = 0.0
    error: Optional[str] = None
    is_inconclusive: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)

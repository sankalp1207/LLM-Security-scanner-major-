"""Pydantic schemas for AI Security Copilot conversations, messages, and intelligence queries."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ConversationCreateRequest(BaseModel):
    """Payload to create a new Copilot conversational session."""

    title: Optional[str] = Field(default="New Security Conversation", max_length=255)
    project_id: Optional[str] = Field(default=None, description="Optional project workspace to bind conversation context")


class ConversationUpdateRequest(BaseModel):
    """Payload to update conversation metadata."""

    title: str = Field(..., min_length=1, max_length=255)


class MessageSendRequest(BaseModel):
    """User message payload sent to the Copilot assistant."""

    content: str = Field(..., min_length=1, max_length=4000, description="User prompt or security inquiry")
    project_id: Optional[str] = Field(default=None, description="Active project workspace context")
    finding_id: Optional[str] = Field(default=None, description="Optional finding ID to attach as explicit context")
    scan_id: Optional[str] = Field(default=None, description="Optional scan ID to attach as explicit context")


class CopilotMessageResponse(BaseModel):
    """Structured response schema for an individual chat message."""

    id: str
    conversation_id: str
    role: str
    content: str
    referenced_evidence_ids: Dict[str, Any] = Field(default_factory=dict)
    created_at: str

    model_config = {"from_attributes": True}


class CopilotConversationResponse(BaseModel):
    """Structured response schema for a Copilot conversation summary."""

    id: str
    user_id: str
    project_id: Optional[str] = None
    title: str
    created_at: str
    updated_at: str
    message_count: int = 0

    model_config = {"from_attributes": True}


class CopilotConversationListResponse(BaseModel):
    """Paginated list of Copilot conversations."""

    total: int
    items: List[CopilotConversationResponse]


class CopilotExplainFindingRequest(BaseModel):
    """Request schema for one-click AI finding explanation."""

    finding_id: Optional[str] = Field(default=None, description="Optional finding ID if not passed via URL path")
    user_query: Optional[str] = Field(default=None, max_length=1000)


class FindingExplanationResponse(BaseModel):
    """Structured evidence-backed explanation and remediation for a vulnerability finding."""

    finding_id: str
    title: str
    category: str
    severity: str
    summary: str
    observed_evidence: Dict[str, Any]
    why_it_matters: str
    root_cause_analysis: str
    recommended_fix: str
    verification_steps: str
    full_text: str


class CopilotCompareScansRequest(BaseModel):
    """Request schema to compare two historical security scans."""

    scan_id_a: str = Field(..., description="Baseline or earlier scan ID")
    scan_id_b: str = Field(..., description="Target or newer scan ID to compare against baseline")
    project_id: Optional[str] = Field(default=None)


class ScanComparisonResponse(BaseModel):
    """Structured comparison metrics and differential findings between two scans."""

    scan_id_a: str
    scan_id_b: str
    scan_a_date: str
    scan_b_date: str
    scan_a_preset: str
    scan_b_preset: str
    new_findings: List[Dict[str, Any]] = Field(default_factory=list)
    resolved_findings: List[Dict[str, Any]] = Field(default_factory=list)
    common_findings: List[Dict[str, Any]] = Field(default_factory=list)
    severity_shift: Dict[str, int] = Field(default_factory=dict)
    coverage_diff: Dict[str, Any] = Field(default_factory=dict)
    regression_summary: str

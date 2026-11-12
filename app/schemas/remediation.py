"""Pydantic schemas for Phase 6 Automated Remediation Assistant."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class RemediationInitRequest(BaseModel):
    """Payload to initiate a remediation lifecycle from an identified vulnerability finding."""

    finding_id: Optional[str] = Field(default=None, description="Target finding ID if not passed via URL path")
    workspace_root: Optional[str] = Field(
        default=None,
        description="Optional explicit workspace root folder for safe source resolution",
    )


class RemediationResponse(BaseModel):
    """Structured response schema representing a remediation lifecycle record."""

    id: str
    project_id: Optional[str] = None
    finding_id: str
    user_id: str
    status: str
    summary: str
    root_cause_analysis: str
    affected_component: str
    created_at: str
    updated_at: str
    latest_patch_id: Optional[str] = None
    latest_retest_status: Optional[str] = None

    model_config = {"from_attributes": True}


class RemediationPatchFile(BaseModel):
    """Structured representation of a single file modification in a patch."""

    path: str
    change_type: str = "modify"  # "modify" or "create"
    reason: str
    diff: str
    original_content: Optional[str] = None
    patched_content: Optional[str] = None


class RemediationPatchResponse(BaseModel):
    """Structured response schema representing a proposed patch version."""

    id: str
    remediation_id: str
    patch_version: int
    summary: str
    files: List[RemediationPatchFile]
    diff_content: str
    source_hashes: Dict[str, str] = Field(default_factory=dict)
    validation_status: str
    validation_errors: List[str] = Field(default_factory=list)
    risks: List[str] = Field(default_factory=list)
    verification_steps: List[str] = Field(default_factory=list)
    created_at: str
    approval_status: Optional[str] = None

    model_config = {"from_attributes": True}


class PatchValidationResponse(BaseModel):
    """Structured safety and applicability validation report for a patch."""

    patch_id: str
    is_valid: bool
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    checked_files: List[str] = Field(default_factory=list)


class PatchApprovalRequest(BaseModel):
    """Payload to record explicit human decision on a proposed patch."""

    decision: str = Field(..., pattern="^(APPROVED|REJECTED|CANCELLED)$")
    reason: Optional[str] = Field(default="", max_length=1000)


class PatchApprovalResponse(BaseModel):
    """Structured response schema for patch approval outcome."""

    id: str
    patch_id: str
    user_id: str
    decision: str
    reason: str
    created_at: str

    model_config = {"from_attributes": True}


class PatchApplyRequest(BaseModel):
    """Payload to apply an approved patch in a controlled local workspace."""

    workspace_root: Optional[str] = Field(
        default=None, description="Optional target workspace directory. Defaults to repo root if permitted."
    )


class PatchApplyResponse(BaseModel):
    """Structured response schema for patch application execution."""

    execution_id: str
    status: str
    applied_files: List[str]
    backup_count: int
    timestamp: str


class VerifyRequest(BaseModel):
    """Optional payload specifying workspace directory for verification."""

    workspace_root: Optional[str] = Field(default=None)


class RemediationVerifyResponse(BaseModel):
    """Structured response schema for post-patch unit testing and vulnerability retest verification."""

    execution_id: str
    remediation_id: str
    patch_id: str
    test_summary: Dict[str, Any]
    retest_status: str
    retest_message: str
    outcome: str
    completed_at: str


class RollbackRequest(BaseModel):
    """Optional payload specifying workspace directory for rollback."""

    workspace_root: Optional[str] = Field(default=None)


class RemediationRollbackResponse(BaseModel):
    """Structured response schema for patch rollback."""

    execution_id: str
    remediation_id: str
    status: str
    restored_files: List[str]
    timestamp: str


class RemediationHistoryItem(BaseModel):
    """Summary item for historical remediation records."""

    id: str
    project_id: Optional[str] = None
    finding_id: str
    finding_title: str
    finding_category: str
    severity: str
    status: str
    summary: str
    patch_count: int = 0
    latest_retest_status: Optional[str] = None
    created_at: str
    updated_at: str

    model_config = {"from_attributes": True}


class RemediationHistoryResponse(BaseModel):
    """Paginated collection of remediation history records."""

    total: int
    items: List[RemediationHistoryItem]

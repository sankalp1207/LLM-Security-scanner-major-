"""FastAPI route endpoints for Phase 6 Automated Remediation Assistant."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.api.auth import get_current_user_id
from app.schemas.remediation import (
    PatchApplyRequest,
    PatchApplyResponse,
    PatchApprovalRequest,
    PatchApprovalResponse,
    PatchValidationResponse,
    RemediationHistoryResponse,
    RemediationInitRequest,
    RemediationPatchResponse,
    RemediationResponse,
    RemediationRollbackResponse,
    RemediationVerifyResponse,
    RollbackRequest,
    VerifyRequest,
)
from app.services.remediation_service import RemediationService

router = APIRouter(prefix="/remediations", tags=["Automated Remediation Assistant"])


@router.post("/findings/{finding_id}", response_model=RemediationResponse)
def initiate_remediation(
    finding_id: str,
    request: Optional[RemediationInitRequest] = None,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> RemediationResponse:
    """Analyze a vulnerability finding and initiate an automated remediation workflow."""
    workspace_root = request.workspace_root if request else None
    return RemediationService.initiate_remediation(
        db=db, finding_id=finding_id, user_id=user_id, workspace_root=workspace_root
    )


@router.get("/{remediation_id}", response_model=RemediationResponse)
def get_remediation(
    remediation_id: str,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> RemediationResponse:
    """Retrieve current status and details of a remediation lifecycle."""
    return RemediationService.get_remediation(db=db, remediation_id=remediation_id, user_id=user_id)


@router.post("/{remediation_id}/generate-fix", response_model=RemediationPatchResponse)
def generate_fix(
    remediation_id: str,
    workspace_root: Optional[str] = Query(None),
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> RemediationPatchResponse:
    """Generate (or regenerate) an automated code patch for a remediation."""
    return RemediationService.generate_fix(
        db=db, remediation_id=remediation_id, user_id=user_id, workspace_root=workspace_root
    )


@router.get("/{remediation_id}/patches", response_model=List[RemediationPatchResponse])
def list_patches(
    remediation_id: str,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> List[RemediationPatchResponse]:
    """List all proposed patch revisions for a remediation."""
    return RemediationService.list_patches(db=db, remediation_id=remediation_id, user_id=user_id)


@router.get("/patches/{patch_id}", response_model=RemediationPatchResponse)
def get_patch(
    patch_id: str,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> RemediationPatchResponse:
    """Retrieve full file diffs, manifest, and validation status of a specific patch."""
    return RemediationService.get_patch(db=db, patch_id=patch_id, user_id=user_id)


@router.post("/patches/{patch_id}/validate", response_model=PatchValidationResponse)
def validate_patch(
    patch_id: str,
    workspace_root: Optional[str] = Query(None),
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> PatchValidationResponse:
    """Re-evaluate patch safety, allowed file extensions, path traversal, and source file drift."""
    return RemediationService.validate_patch(
        db=db, patch_id=patch_id, user_id=user_id, workspace_root=workspace_root
    )


@router.post("/patches/{patch_id}/approve", response_model=PatchApprovalResponse)
def approve_patch(
    patch_id: str,
    request: Optional[PatchApprovalRequest] = None,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> PatchApprovalResponse:
    """Record explicit human approval for a validated patch before application."""
    decision = request.decision if request else "APPROVED"
    reason = request.reason if request else ""
    return RemediationService.record_approval(
        db=db, patch_id=patch_id, user_id=user_id, decision=decision, reason=reason
    )


@router.post("/patches/{patch_id}/reject", response_model=PatchApprovalResponse)
def reject_patch(
    patch_id: str,
    request: Optional[PatchApprovalRequest] = None,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> PatchApprovalResponse:
    """Record human rejection of a proposed patch."""
    reason = request.reason if request else "Rejected by operator"
    return RemediationService.record_approval(
        db=db, patch_id=patch_id, user_id=user_id, decision="REJECTED", reason=reason
    )


@router.post("/patches/{patch_id}/apply", response_model=PatchApplyResponse)
def apply_patch(
    patch_id: str,
    request: Optional[PatchApplyRequest] = None,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> PatchApplyResponse:
    """Apply an approved patch in a controlled workspace with automatic backup creation."""
    workspace_root = request.workspace_root if request else None
    return RemediationService.apply_patch(
        db=db, patch_id=patch_id, user_id=user_id, workspace_root=workspace_root
    )


@router.post("/{remediation_id}/verify", response_model=RemediationVerifyResponse)
async def verify_remediation(
    remediation_id: str,
    request: Optional[VerifyRequest] = None,
    workspace_root: Optional[str] = Query(None),
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> RemediationVerifyResponse:
    """Execute validation tests and retest the original vulnerability against the target."""
    ws_root = (request.workspace_root if request and request.workspace_root else None) or workspace_root
    return await RemediationService.verify_remediation(
        db=db, remediation_id=remediation_id, user_id=user_id, workspace_root=ws_root
    )


@router.post("/{remediation_id}/rollback", response_model=RemediationRollbackResponse)
def rollback_remediation(
    remediation_id: str,
    request: Optional[RollbackRequest] = None,
    workspace_root: Optional[str] = Query(None),
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> RemediationRollbackResponse:
    """Revert applied patch files using the execution backup manifest."""
    ws_root = (request.workspace_root if request and request.workspace_root else None) or workspace_root
    return RemediationService.rollback_remediation(
        db=db, remediation_id=remediation_id, user_id=user_id, workspace_root=ws_root
    )


@router.get("/projects/{project_id}/history", response_model=RemediationHistoryResponse)
def list_project_remediation_history(
    project_id: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> RemediationHistoryResponse:
    """List historical remediation lifecycle records for a project workspace."""
    return RemediationService.list_project_remediations(
        db=db, project_id=project_id, user_id=user_id, skip=skip, limit=limit
    )


@router.get("/patches/{patch_id}/download")
def download_patch(
    patch_id: str,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> Response:
    """Download standard unified diff patch file for git apply or human inspection."""
    diff_text = RemediationService.download_patch(db=db, patch_id=patch_id, user_id=user_id)
    return Response(
        content=diff_text,
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename=remediation_{patch_id[:8]}.patch"},
    )

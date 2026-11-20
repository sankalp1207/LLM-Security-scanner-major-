"""Finding review and remediation retesting route handlers."""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.api.auth import get_current_user_id
from app.schemas.scans import FindingResponse
from app.schemas.remediation import RemediationInitRequest, RemediationResponse
from app.services.finding_service import FindingService
from app.services.remediation_service import RemediationService

router = APIRouter(prefix="/findings", tags=["Findings"])


@router.get("", response_model=List[FindingResponse])
def list_findings(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    category: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    retest_status: Optional[str] = Query(None),
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> List[FindingResponse]:
    """List security findings across all scans with pagination and filters."""
    findings = FindingService.list_findings(
        db=db,
        skip=skip,
        limit=limit,
        category=category,
        severity=severity,
        retest_status=retest_status,
        user_id=user_id,
    )
    return [
        FindingResponse(
            id=f.id,
            scan_id=f.scan_id,
            category=f.category,
            severity=f.severity,
            title=f.title,
            description=f.description,
            evidence=f.evidence,
            confidence_score=f.confidence_score,
            target_component=f.target_component,
            affected_test_case=f.affected_test_case,
            detection_method=f.detection_method,
            remediation=f.remediation,
            creation_timestamp=f.creation_timestamp.isoformat(),
            retest_status=f.retest_status,
        )
        for f in findings
    ]


@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding(
    finding_id: str,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> FindingResponse:
    """Retrieve details for a single security finding."""
    f = FindingService.get_finding(db=db, finding_id=finding_id, user_id=user_id)
    return FindingResponse(
        id=f.id,
        scan_id=f.scan_id,
        category=f.category,
        severity=f.severity,
        title=f.title,
        description=f.description,
        evidence=f.evidence,
        confidence_score=f.confidence_score,
        target_component=f.target_component,
        affected_test_case=f.affected_test_case,
        detection_method=f.detection_method,
        remediation=f.remediation,
        creation_timestamp=f.creation_timestamp.isoformat(),
        retest_status=f.retest_status,
    )


@router.post("/{finding_id}/retest")
def retest_finding(
    finding_id: str,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Retest an identified vulnerability to verify mitigation effectiveness."""
    return FindingService.retest_finding(db=db, finding_id=finding_id, user_id=user_id)


@router.post("/{finding_id}/remediation", response_model=RemediationResponse)
def create_finding_remediation(
    finding_id: str,
    request: Optional[RemediationInitRequest] = None,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> RemediationResponse:
    """Analyze a vulnerability finding and generate automated remediation."""
    ws_root = request.workspace_root if request else None
    return RemediationService.initiate_remediation(
        db=db, finding_id=finding_id, user_id=user_id, workspace_root=ws_root
    )

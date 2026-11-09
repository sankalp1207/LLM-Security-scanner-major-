"""FastAPI routes for Project management, target configuration, connection testing, and onboarding."""

from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.database.repository import ProjectRepository
from app.schemas.projects import (
    ConnectionVerificationRequest,
    ConnectionVerificationResponse,
    OnboardingCompleteRequest,
    OnboardingStatusResponse,
    ProjectCreateRequest,
    ProjectListResponse,
    ProjectResponse,
    ProjectUpdateRequest,
)
from app.schemas.scans import (
    ProjectScanCreateRequest,
    ScanListResponse,
    ScanResponse,
)
from app.services.capability_service import CapabilityService, TargetCapabilityReport
from app.services.project_service import ProjectService
from app.services.scan_service import ScanService

router = APIRouter(tags=["Projects & Onboarding"])


def get_current_user_id(x_user_id: Optional[str] = Header(None)) -> str:
    """Retrieve current authenticated user identifier from header or default."""
    return x_user_id.strip() if x_user_id and x_user_id.strip() else "default_user"


# -----------------------------------------------------------------------------
# ONBOARDING ENDPOINTS
# -----------------------------------------------------------------------------
@router.get("/onboarding/status", response_model=OnboardingStatusResponse)
def get_onboarding_status(
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> OnboardingStatusResponse:
    """Check onboarding completion state for current user."""
    return ProjectService.get_onboarding_status(db=db, user_id=user_id)


@router.post("/onboarding/complete", response_model=OnboardingStatusResponse)
def complete_onboarding(
    request: OnboardingCompleteRequest,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> OnboardingStatusResponse:
    """Acknowledge and persist onboarding completion."""
    return ProjectService.complete_onboarding(db=db, request=request, user_id=user_id)


@router.post("/onboarding/reset", response_model=OnboardingStatusResponse)
def reset_onboarding(
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> OnboardingStatusResponse:
    """Reset onboarding state to allow re-running setup from settings."""
    return ProjectService.reset_onboarding(db=db, user_id=user_id)


# -----------------------------------------------------------------------------
# PROJECT CRUD ENDPOINTS
# -----------------------------------------------------------------------------
@router.post("/projects", response_model=ProjectResponse)
def create_project(
    request: ProjectCreateRequest,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> ProjectResponse:
    """Provision a new security evaluation project."""
    return ProjectService.create_project(db=db, request=request, owner_id=user_id)


@router.get("/projects", response_model=ProjectListResponse)
def list_projects(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    include_archived: bool = Query(False),
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> ProjectListResponse:
    """List projects accessible to the current user."""
    return ProjectService.list_projects(
        db=db,
        owner_id=user_id,
        skip=skip,
        limit=limit,
        include_archived=include_archived,
    )


@router.get("/projects/{project_id}", response_model=ProjectResponse)
def get_project(
    project_id: str,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> ProjectResponse:
    """Retrieve full details for a single project."""
    return ProjectService.get_project(db=db, project_id=project_id, owner_id=user_id)


@router.patch("/projects/{project_id}", response_model=ProjectResponse)
def update_project(
    project_id: str,
    request: ProjectUpdateRequest,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> ProjectResponse:
    """Update project metadata, scope, or archive status."""
    return ProjectService.update_project(
        db=db, project_id=project_id, request=request, owner_id=user_id
    )


@router.delete("/projects/{project_id}")
def delete_project(
    project_id: str,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Delete a project and its target configuration."""
    return ProjectService.delete_project(db=db, project_id=project_id, owner_id=user_id)


# -----------------------------------------------------------------------------
# CONNECTION VERIFICATION & PREFERENCES
# -----------------------------------------------------------------------------
@router.post(
    "/projects/{project_id}/verify-connection",
    response_model=ConnectionVerificationResponse,
)
async def verify_project_connection(
    project_id: str,
    override_req: Optional[ConnectionVerificationRequest] = None,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> ConnectionVerificationResponse:
    """Execute live diagnostic connection verification for project target."""
    return await ProjectService.verify_project_connection(
        db=db,
        project_id=project_id,
        override_req=override_req,
        owner_id=user_id,
    )


@router.get("/projects/{project_id}/preferences")
def get_project_preferences(
    project_id: str,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Get security testing preferences for project."""
    return ProjectService.get_preferences(db=db, project_id=project_id, owner_id=user_id)


@router.patch("/projects/{project_id}/preferences")
def update_project_preferences(
    project_id: str,
    preferences: Dict[str, Any],
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Update security testing preferences for project."""
    return ProjectService.update_preferences(
        db=db, project_id=project_id, preferences=preferences, owner_id=user_id
    )


# -----------------------------------------------------------------------------
# PROJECT SCANNING & CAPABILITY RESOLUTION (PHASE 3)
# -----------------------------------------------------------------------------
@router.get(
    "/projects/{project_id}/scan-capabilities",
    response_model=TargetCapabilityReport,
)
def get_project_scan_capabilities(
    project_id: str,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> TargetCapabilityReport:
    """Evaluate target capabilities and resolve supported/skipped threat categories."""
    project = ProjectRepository.get_project(db, project_id=project_id, owner_id=user_id)
    if not project:
        raise HTTPException(status_code=404, detail=f"Project '{project_id}' not found.")
    return CapabilityService.resolve_project_capabilities(project)


@router.post("/projects/{project_id}/scans", response_model=ScanResponse)
def create_project_scan(
    project_id: str,
    request: ProjectScanCreateRequest,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> ScanResponse:
    """Initiate a one-click security scan scoped to an enterprise project."""
    scan = ScanService.create_and_run_project_scan(
        db=db, project_id=project_id, request=request, user_id=user_id
    )
    findings = ScanService.get_findings_for_scan(db=db, scan_id=scan.id, user_id=user_id)
    return ScanResponse(
        id=scan.id,
        project_id=scan.project_id,
        user_id=scan.user_id,
        preset=scan.preset,
        target_identifier=scan.target_identifier,
        status=scan.status,
        configuration=scan.configuration,
        configuration_snapshot=scan.configuration_snapshot,
        start_timestamp=scan.start_timestamp.isoformat(),
        completion_timestamp=scan.completion_timestamp.isoformat() if scan.completion_timestamp else None,
        summary=scan.summary,
        scanner_version=scan.scanner_version,
        findings_count=len(findings),
        total_tests=scan.total_tests,
        completed_tests=scan.completed_tests,
        passed_tests=scan.passed_tests,
        failed_tests=scan.failed_tests,
        inconclusive_tests=scan.inconclusive_tests,
        skipped_tests=scan.skipped_tests,
        execution_errors=scan.execution_errors,
        cancellation_reason=scan.cancellation_reason,
        failure_reason=scan.failure_reason,
    )


@router.get("/projects/{project_id}/scans", response_model=ScanListResponse)
def list_project_scans(
    project_id: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    status: Optional[str] = Query(None),
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> ScanListResponse:
    """Retrieve paginated scan records scoped to an enterprise project."""
    res = ScanService.list_project_scans(
        db=db, project_id=project_id, user_id=user_id, skip=skip, limit=limit, status=status
    )
    items = []
    for s in res["items"]:
        findings = ScanService.get_findings_for_scan(db=db, scan_id=s.id, user_id=user_id)
        items.append(
            ScanResponse(
                id=s.id,
                project_id=s.project_id,
                user_id=s.user_id,
                preset=s.preset,
                target_identifier=s.target_identifier,
                status=s.status,
                configuration=s.configuration,
                configuration_snapshot=s.configuration_snapshot,
                start_timestamp=s.start_timestamp.isoformat(),
                completion_timestamp=s.completion_timestamp.isoformat() if s.completion_timestamp else None,
                summary=s.summary,
                scanner_version=s.scanner_version,
                findings_count=len(findings),
                total_tests=s.total_tests,
                completed_tests=s.completed_tests,
                passed_tests=s.passed_tests,
                failed_tests=s.failed_tests,
                inconclusive_tests=s.inconclusive_tests,
                skipped_tests=s.skipped_tests,
                execution_errors=s.execution_errors,
                cancellation_reason=s.cancellation_reason,
                failure_reason=s.failure_reason,
            )
        )
    return ScanListResponse(total=res["total"], items=items)


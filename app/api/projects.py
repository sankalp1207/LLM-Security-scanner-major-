"""FastAPI routes for Project management, target configuration, connection testing, and onboarding."""

from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, Header, Query
from sqlalchemy.orm import Session

from app.database.connection import get_db
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
from app.services.project_service import ProjectService

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


"""Service orchestrating multi-project lifecycle, target management, and onboarding workflows."""

from typing import Any, Dict, List, Optional
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.database.models import Project, TargetConfiguration
from app.database.repository import (
    FindingRepository,
    ProjectRepository,
    ScanRepository,
    TargetConfigurationRepository,
    UserOnboardingRepository,
)
from app.schemas.projects import (
    ConnectionVerificationRequest,
    ConnectionVerificationResponse,
    OnboardingCompleteRequest,
    OnboardingStatusResponse,
    ProjectCreateRequest,
    ProjectListResponse,
    ProjectResponse,
    ProjectUpdateRequest,
    TargetConfigurationCreate,
    TargetConfigurationResponse,
)
from app.services.connection_verifier import ConnectionVerifier
from app.services.crypto_service import CryptoService


class ProjectService:
    """Enterprise business logic for projects, target setups, and onboarding."""

    @classmethod
    def _to_target_response(
        cls,
        tc: Optional[TargetConfiguration],
    ) -> Optional[TargetConfigurationResponse]:
        """Convert TargetConfiguration model to safe client response with masked secrets."""
        if not tc:
            return None
        decrypted = CryptoService.decrypt_credential(tc.encrypted_credential)
        masked = CryptoService.mask_credential(decrypted) if decrypted else ""
        return TargetConfigurationResponse(
            id=tc.id,
            project_id=tc.project_id,
            provider=tc.provider,
            endpoint_url=tc.endpoint_url,
            model_identifier=tc.model_identifier,
            auth_type=tc.auth_type,
            masked_credential=masked,
            connection_timeout=tc.connection_timeout,
            connection_status=tc.connection_status,
            last_verified_at=tc.last_verified_at.isoformat() if tc.last_verified_at else None,
            verification_details=tc.verification_details or {},
        )

    @classmethod
    def _to_project_response(
        cls,
        db: Session,
        project: Project,
    ) -> ProjectResponse:
        """Convert Project model to ProjectResponse with aggregated metrics."""
        tc_resp = cls._to_target_response(project.target_configuration)

        # Calculate scan stats for project
        scans = (
            db.query(ScanRepository.get_scan.__annotations__.get("return", Project))
            if False else []
        )
        # Fetch scans linked to project
        from app.database.models import Scan
        project_scans = db.query(Scan).filter(Scan.project_id == project.id).order_by(Scan.start_timestamp.desc()).all()
        scans_count = len(project_scans)
        last_scan_date = project_scans[0].start_timestamp.isoformat() if project_scans else None

        # Calculate security posture score if scans exist
        posture_score: Optional[int] = None
        if project_scans:
            all_findings = []
            for s in project_scans:
                all_findings.extend(FindingRepository.list_findings_by_scan(db, s.id))
            crit_unres = sum(1 for f in all_findings if f.severity == "CRITICAL" and f.retest_status != "RETEST_PASSED")
            high_unres = sum(1 for f in all_findings if f.severity == "HIGH" and f.retest_status != "RETEST_PASSED")
            med_unres = sum(1 for f in all_findings if f.severity == "MEDIUM" and f.retest_status != "RETEST_PASSED")
            low_unres = sum(1 for f in all_findings if f.severity == "LOW" and f.retest_status != "RETEST_PASSED")
            resolved = sum(1 for f in all_findings if f.retest_status == "RETEST_PASSED")

            deductions = (crit_unres * 15) + (high_unres * 8) + (med_unres * 3) + (low_unres * 1)
            bonuses = min(20, resolved * 5)
            posture_score = max(0, min(100, 100 - deductions + bonuses))

        return ProjectResponse(
            id=project.id,
            owner_id=project.owner_id,
            name=project.name,
            description=project.description,
            application_type=project.application_type,
            environment=project.environment,
            target_type=project.target_type,
            target_configuration=tc_resp,
            default_scan_preferences=project.default_scan_preferences or {},
            is_archived=project.is_archived,
            onboarding_completed=project.onboarding_completed,
            created_at=project.created_at.isoformat(),
            updated_at=project.updated_at.isoformat(),
            last_scan_date=last_scan_date,
            scans_count=scans_count,
            security_posture_score=posture_score,
        )

    @classmethod
    def create_project(
        cls,
        db: Session,
        request: ProjectCreateRequest,
        owner_id: str = "default_user",
    ) -> ProjectResponse:
        """Create new project with optional target configuration and credentials encryption."""
        # Enforce unique project name per owner
        existing = ProjectRepository.get_project_by_name(db, name=request.name.strip(), owner_id=owner_id)
        if existing:
            raise HTTPException(
                status_code=400,
                detail=f"Project with name '{request.name}' already exists in your workspace.",
            )

        project = ProjectRepository.create_project(
            db=db,
            name=request.name.strip(),
            owner_id=owner_id,
            description=request.description or "",
            application_type=request.application_type,
            environment=request.environment,
            target_type=request.target_type,
            default_scan_preferences=request.default_scan_preferences,
        )

        # Handle target configuration
        if request.target_configuration:
            tc_req = request.target_configuration
            enc_secret = CryptoService.encrypt_credential(tc_req.credential) if tc_req.credential else ""
            TargetConfigurationRepository.upsert_configuration(
                db=db,
                project_id=project.id,
                provider=tc_req.provider,
                endpoint_url=tc_req.endpoint_url.strip(),
                model_identifier=tc_req.model_identifier or "",
                auth_type=tc_req.auth_type,
                encrypted_credential=enc_secret,
                connection_timeout=tc_req.connection_timeout,
            )
        elif request.target_type == "demo":
            # Default demo setup
            TargetConfigurationRepository.upsert_configuration(
                db=db,
                project_id=project.id,
                provider="demo",
                endpoint_url="http://127.0.0.1:8000/api/v1/demo-rag/query",
                model_identifier="demo-rag-v1",
                auth_type="none",
                encrypted_credential="",
                connection_timeout=10.0,
            )

        db.refresh(project)
        return cls._to_project_response(db, project)

    @classmethod
    def get_project(
        cls,
        db: Session,
        project_id: str,
        owner_id: str = "default_user",
    ) -> ProjectResponse:
        """Fetch project by ID with ownership enforcement."""
        project = ProjectRepository.get_project(db, project_id=project_id, owner_id=owner_id)
        if not project:
            raise HTTPException(status_code=404, detail=f"Project '{project_id}' not found.")
        return cls._to_project_response(db, project)

    @classmethod
    def list_projects(
        cls,
        db: Session,
        owner_id: str = "default_user",
        skip: int = 0,
        limit: int = 50,
        include_archived: bool = False,
    ) -> ProjectListResponse:
        """Retrieve paginated project list for owner."""
        projects = ProjectRepository.list_projects(
            db=db, owner_id=owner_id, skip=skip, limit=limit, include_archived=include_archived
        )
        total = ProjectRepository.count_projects(
            db=db, owner_id=owner_id, include_archived=include_archived
        )
        items = [cls._to_project_response(db, p) for p in projects]
        return ProjectListResponse(total=total, items=items)

    @classmethod
    def update_project(
        cls,
        db: Session,
        project_id: str,
        request: ProjectUpdateRequest,
        owner_id: str = "default_user",
    ) -> ProjectResponse:
        """Update mutable fields on project."""
        project = ProjectRepository.get_project(db, project_id=project_id, owner_id=owner_id)
        if not project:
            raise HTTPException(status_code=404, detail=f"Project '{project_id}' not found.")

        # Check duplicate name if renamed
        if request.name and request.name.strip() != project.name:
            dup = ProjectRepository.get_project_by_name(db, name=request.name.strip(), owner_id=owner_id)
            if dup:
                raise HTTPException(status_code=400, detail=f"Project with name '{request.name}' already exists.")

        updates = {
            "name": request.name.strip() if request.name else None,
            "description": request.description,
            "application_type": request.application_type,
            "environment": request.environment,
            "target_type": request.target_type,
            "default_scan_preferences": request.default_scan_preferences,
            "is_archived": request.is_archived,
        }
        updated = ProjectRepository.update_project(db, project_id=project_id, updates=updates, owner_id=owner_id)
        return cls._to_project_response(db, updated)

    @classmethod
    def delete_project(
        cls,
        db: Session,
        project_id: str,
        owner_id: str = "default_user",
    ) -> Dict[str, Any]:
        """Delete project under explicit ownership verification."""
        success = ProjectRepository.delete_project(db, project_id=project_id, owner_id=owner_id)
        if not success:
            raise HTTPException(status_code=404, detail=f"Project '{project_id}' not found.")
        return {"status": "deleted", "project_id": project_id}

    @classmethod
    def update_preferences(
        cls,
        db: Session,
        project_id: str,
        preferences: Dict[str, Any],
        owner_id: str = "default_user",
    ) -> Dict[str, Any]:
        """Update default security scanning preferences for a project."""
        project = ProjectRepository.get_project(db, project_id=project_id, owner_id=owner_id)
        if not project:
            raise HTTPException(status_code=404, detail=f"Project '{project_id}' not found.")

        merged = {**project.default_scan_preferences, **preferences}
        ProjectRepository.update_project(db, project_id=project_id, updates={"default_scan_preferences": merged}, owner_id=owner_id)
        return {"status": "updated", "preferences": merged}

    @classmethod
    def get_preferences(
        cls,
        db: Session,
        project_id: str,
        owner_id: str = "default_user",
    ) -> Dict[str, Any]:
        """Get security scanning preferences for a project."""
        project = ProjectRepository.get_project(db, project_id=project_id, owner_id=owner_id)
        if not project:
            raise HTTPException(status_code=404, detail=f"Project '{project_id}' not found.")
        return project.default_scan_preferences or {}

    @classmethod
    async def verify_project_connection(
        cls,
        db: Session,
        project_id: str,
        override_req: Optional[ConnectionVerificationRequest] = None,
        owner_id: str = "default_user",
    ) -> ConnectionVerificationResponse:
        """Perform non-adversarial connection test for a project's configured target."""
        project = ProjectRepository.get_project(db, project_id=project_id, owner_id=owner_id)
        if not project:
            raise HTTPException(status_code=404, detail=f"Project '{project_id}' not found.")

        tc = project.target_configuration
        endpoint_url = (override_req.endpoint_url if override_req and override_req.endpoint_url else (tc.endpoint_url if tc else ""))
        if not endpoint_url:
            raise HTTPException(status_code=400, detail="Target endpoint URL is not configured.")

        provider = (override_req.provider if override_req and override_req.provider else (tc.provider if tc else "demo"))
        auth_type = (override_req.auth_type if override_req and override_req.auth_type else (tc.auth_type if tc else "none"))
        target_type = (override_req.target_type if override_req and override_req.target_type else project.target_type)
        timeout = (override_req.connection_timeout if override_req and override_req.connection_timeout else (tc.connection_timeout if tc else 10.0))

        # Securely retrieve in-memory credential (never logged or exposed)
        decrypted_secret = None
        if override_req and override_req.credential:
            decrypted_secret = override_req.credential
        elif tc and tc.encrypted_credential:
            decrypted_secret = CryptoService.decrypt_credential(tc.encrypted_credential)

        # Run verification
        res = await ConnectionVerifier.verify_connection(
            endpoint_url=endpoint_url,
            target_type=target_type,
            provider=provider,
            auth_type=auth_type,
            credential=decrypted_secret,
            timeout_seconds=timeout,
        )

        # Update persisted verification status
        if tc:
            TargetConfigurationRepository.update_verification_status(
                db=db,
                project_id=project.id,
                status=res.status,
                details={"latency_ms": res.latency_ms, "status_code": res.status_code, "message": res.message},
            )

        return res

    @classmethod
    def get_onboarding_status(
        cls,
        db: Session,
        user_id: str = "default_user",
    ) -> OnboardingStatusResponse:
        """Fetch onboarding completion status for user."""
        record = UserOnboardingRepository.get_status(db, user_id=user_id)
        has_projects = ProjectRepository.count_projects(db, owner_id=user_id) > 0
        if not record:
            return OnboardingStatusResponse(
                user_id=user_id,
                is_completed=False,
                selected_demo=False,
                active_project_id=None,
                has_projects=has_projects,
            )
        return OnboardingStatusResponse(
            user_id=user_id,
            is_completed=record.is_completed,
            selected_demo=record.selected_demo,
            active_project_id=record.active_project_id,
            has_projects=has_projects,
        )

    @classmethod
    def complete_onboarding(
        cls,
        db: Session,
        request: OnboardingCompleteRequest,
        user_id: str = "default_user",
    ) -> OnboardingStatusResponse:
        """Record onboarding completion for user."""
        record = UserOnboardingRepository.complete_onboarding(
            db=db,
            user_id=user_id,
            selected_demo=request.selected_demo,
            active_project_id=request.project_id,
        )
        return cls.get_onboarding_status(db, user_id=user_id)

    @classmethod
    def reset_onboarding(
        cls,
        db: Session,
        user_id: str = "default_user",
    ) -> OnboardingStatusResponse:
        """Allow resetting onboarding from settings."""
        UserOnboardingRepository.reset_onboarding(db, user_id=user_id)
        return cls.get_onboarding_status(db, user_id=user_id)


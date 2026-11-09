"""Service orchestrating scan creation, preset resolution, execution, and telemetry persistence."""

import asyncio
import concurrent.futures
import logging
from typing import Any, Dict, List, Optional

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.database.connection import SessionLocal
from app.database.models import Finding, Project, Scan, TestExecution
from app.database.repository import (
    FindingRepository,
    ProjectRepository,
    ScanRepository,
    TestExecutionRepository,
)
from app.scanner.orchestrator import ScanOrchestrator
from app.scanner.target_client import TargetClient
from app.schemas.presets import get_preset_by_id
from app.schemas.events import ScanEventType
from app.schemas.scans import (
    ProjectScanCreateRequest,
    ScanCreateRequest,
    TestExecutionListResponse,
    TestExecutionResponse,
)
from app.services.capability_service import CapabilityService
from app.services.connection_verifier import ConnectionVerifier
from app.services.event_service import ScanEventService

logger = logging.getLogger("scan_service")


class ScanService:
    """Business logic for scan management, presets, and execution."""

    @staticmethod
    def _execute_in_event_loop(
        orchestrator: ScanOrchestrator,
        scan_id: str,
        target_url: str,
        categories: Any,
        max_concurrency: int,
        timeout_seconds: float,
        external_authorized: bool,
        http_client: Any,
        enable_mutation_fuzzing: bool,
        mutation_types: Any,
        max_tests: Optional[int] = None,
        preset: str = "quick_scan",
        skipped_categories: Optional[List[dict]] = None,
    ) -> Scan:
        """Helper to run async orchestrator within any thread or running loop context."""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        coro = orchestrator.execute_scan(
            scan_id=scan_id,
            target_url=target_url,
            categories=categories,
            max_concurrency=max_concurrency,
            timeout_seconds=timeout_seconds,
            external_authorized=external_authorized,
            http_client=http_client,
            enable_mutation_fuzzing=enable_mutation_fuzzing,
            mutation_types=mutation_types,
            max_tests=max_tests,
            preset=preset,
            skipped_categories=skipped_categories,
        )

        if loop.is_running():
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                def _worker():
                    new_loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(new_loop)
                    try:
                        return new_loop.run_until_complete(coro)
                    finally:
                        new_loop.close()

                return executor.submit(_worker).result()
        else:
            return loop.run_until_complete(coro)

    @classmethod
    def create_and_run_project_scan(
        cls,
        db: Session,
        project_id: str,
        request: ProjectScanCreateRequest,
        user_id: str = "default_user",
        http_client: Any = None,
    ) -> Scan:
        """
        Validate, scope, queue, and execute a security scan against a project's configured target.
        Enforces server-side maximum limits, SSRF protection, and capability resolution.
        """
        # 1. Project Verification & Ownership Check
        project = ProjectRepository.get_project(db, project_id=project_id, owner_id=user_id)
        if not project:
            # Check if project exists under another user to distinguish 404 from 403
            proj_exists = db.query(Project).filter(Project.id == project_id).first()
            if proj_exists:
                raise HTTPException(status_code=403, detail="Access denied: you do not have permission to scan this project.")
            raise HTTPException(status_code=404, detail=f"Project '{project_id}' not found.")

        if project.is_archived:
            raise HTTPException(status_code=400, detail="Cannot initiate scan: project is archived.")

        # 2. Target Configuration Check
        tc = project.target_configuration
        if not tc or not tc.endpoint_url:
            raise HTTPException(status_code=400, detail="Target endpoint URL is not configured for this project.")

        endpoint_url = tc.endpoint_url.strip()

        # 3. External Target Authorization Acknowledgement
        is_local_allowed = project.target_type in ("demo", "local_llm")
        is_external = project.target_type == "external_api" or not is_local_allowed
        if is_external and not request.external_target_authorized:
            raise HTTPException(
                status_code=400,
                detail="Scanning an external target requires explicit authorization acknowledgement. Set external_target_authorized=True in scan request.",
            )

        # 4. Network Policy & SSRF Verification
        is_safe, error_reason = ConnectionVerifier.validate_destination_ssrf(
            endpoint_url, allow_local=is_local_allowed
        )
        if not is_safe:
            raise HTTPException(
                status_code=400,
                detail=f"Target URL violates network security policy: {error_reason}",
            )

        # 5. Preset & Capability Resolution
        preset_config = get_preset_by_id(request.preset)
        if not preset_config:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid scan preset '{request.preset}'. Supported presets are: quick_scan, full_scan, deep_red_team.",
            )

        capabilities_report = CapabilityService.resolve_project_capabilities(project, tc)

        # Determine effective categories to test
        if request.categories:
            # User specified categories: keep those that are applicable
            chosen_categories = [
                c for c in request.categories if c in capabilities_report.applicable_categories
            ]
        else:
            chosen_categories = [
                c for c in preset_config.enabled_categories if c in capabilities_report.applicable_categories
            ]

        # Enforce server-side maximum limits
        max_tests = min(
            request.custom_max_tests or preset_config.max_tests,
            200,
        )
        max_concurrency = min(
            request.custom_concurrency or preset_config.max_concurrency,
            10,
        )
        timeout_seconds = min(
            request.custom_timeout_seconds or preset_config.request_timeout,
            60.0,
        )
        enable_fuzzing = (
            request.enable_mutation_fuzzing
            if request.enable_mutation_fuzzing is not None
            else preset_config.mutation_fuzzing
        )

        # 6. Build Safe Configuration Snapshot (No plaintext secrets)
        config_snapshot = {
            "preset": preset_config.preset_id,
            "target_url": endpoint_url,
            "target_type": project.target_type,
            "provider": tc.provider,
            "categories": chosen_categories,
            "max_tests": max_tests,
            "max_concurrency": max_concurrency,
            "timeout_seconds": timeout_seconds,
            "enable_mutation_fuzzing": enable_fuzzing,
            "mutation_types": request.mutation_types,
            "detected_capabilities": capabilities_report.detected_capabilities,
            "skipped_categories": capabilities_report.skipped_categories,
            "external_target_authorized": request.external_target_authorized,
        }

        # 7. Create Scan Record (Lifecycle: CREATED -> QUEUED)
        scan = ScanRepository.create_scan(
            db=db,
            target_identifier=endpoint_url,
            configuration=config_snapshot,
            project_id=project.id,
            user_id=user_id,
            preset=preset_config.preset_id,
            target_configuration_id=tc.id,
            configuration_snapshot=config_snapshot,
            status="CREATED",
            total_tests=max_tests + len(capabilities_report.skipped_categories),
        )

        # Transition to QUEUED
        ScanRepository.update_scan_status(db=db, scan_id=scan.id, status="QUEUED")

        # Emit initial lifecycle events
        ScanEventService.publish_event(
            scan_id=scan.id,
            event_type=ScanEventType.SCAN_CREATED.value,
            payload={
                "project_id": project.id,
                "preset": preset_config.preset_id,
                "target_url": endpoint_url,
                "total_tests": scan.total_tests,
            },
            db=db,
            persist=True,
        )
        ScanEventService.publish_event(
            scan_id=scan.id,
            event_type=ScanEventType.SCAN_QUEUED.value,
            payload={
                "project_id": project.id,
                "preset": preset_config.preset_id,
                "total_tests": scan.total_tests,
            },
            db=db,
            persist=True,
        )

        # 8. Execution
        if http_client is None and "testserver" in endpoint_url:
            from httpx import ASGITransport, AsyncClient
            from app.main import app
            http_client = AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver")

        if request.sync_execute:
            orchestrator = ScanOrchestrator(db=db)
            scan = cls._execute_in_event_loop(
                orchestrator=orchestrator,
                scan_id=scan.id,
                target_url=endpoint_url,
                categories=chosen_categories,
                max_concurrency=max_concurrency,
                timeout_seconds=timeout_seconds,
                external_authorized=request.external_target_authorized,
                http_client=http_client,
                enable_mutation_fuzzing=enable_fuzzing,
                mutation_types=request.mutation_types,
                max_tests=max_tests,
                preset=preset_config.preset_id,
                skipped_categories=capabilities_report.skipped_categories,
            )
            return scan
        else:
            # Asynchronous background execution
            def _background_scan_task(s_id: str):
                task_db = SessionLocal()
                try:
                    task_orch = ScanOrchestrator(db=task_db)
                    cls._execute_in_event_loop(
                        orchestrator=task_orch,
                        scan_id=s_id,
                        target_url=endpoint_url,
                        categories=chosen_categories,
                        max_concurrency=max_concurrency,
                        timeout_seconds=timeout_seconds,
                        external_authorized=request.external_target_authorized,
                        http_client=http_client,
                        enable_mutation_fuzzing=enable_fuzzing,
                        mutation_types=request.mutation_types,
                        max_tests=max_tests,
                        preset=preset_config.preset_id,
                        skipped_categories=capabilities_report.skipped_categories,
                    )
                except Exception as exc:
                    logger.error(f"Error in background scan {s_id}: {exc}", exc_info=True)
                    ScanRepository.update_scan_status(
                        db=task_db,
                        scan_id=s_id,
                        status="FAILED",
                        failure_reason=str(exc),
                    )
                finally:
                    task_db.close()

            # Dispatch background worker
            loop = asyncio.get_event_loop()
            loop.run_in_executor(None, _background_scan_task, scan.id)
            return ScanRepository.get_scan(db, scan.id)

    @classmethod
    def create_and_run_scan(
        cls,
        db: Session,
        request: ScanCreateRequest,
        http_client: Any = None,
        sync_execute: bool = True,
    ) -> Scan:
        """Legacy direct scan initiation."""
        validation = TargetClient.validate_target(
            target_url=request.target_url,
            external_authorized=request.external_target_authorized,
        )
        if not validation.is_valid:
            raise HTTPException(status_code=400, detail=validation.error_message)

        config_dict = {
            "target_url": request.target_url,
            "categories": [c.value if hasattr(c, "value") else str(c) for c in request.categories] if request.categories else "all",
            "max_concurrency": request.max_concurrency,
            "timeout_seconds": request.timeout_seconds,
            "external_authorized": request.external_target_authorized,
            "enable_mutation_fuzzing": request.enable_mutation_fuzzing,
            "mutation_types": request.mutation_types,
        }
        scan = ScanRepository.create_scan(
            db=db,
            target_identifier=request.target_url,
            configuration=config_dict,
            configuration_snapshot=config_dict,
            status="QUEUED",
        )
        ScanEventService.publish_event(
            scan_id=scan.id,
            event_type=ScanEventType.SCAN_CREATED.value,
            payload={"target_url": request.target_url},
            db=db,
            persist=True,
        )
        ScanEventService.publish_event(
            scan_id=scan.id,
            event_type=ScanEventType.SCAN_QUEUED.value,
            payload={"target_url": request.target_url},
            db=db,
            persist=True,
        )

        if http_client is None and "testserver" in request.target_url:
            from httpx import ASGITransport, AsyncClient
            from app.main import app
            http_client = AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver")

        if sync_execute:
            orchestrator = ScanOrchestrator(db=db)
            scan = cls._execute_in_event_loop(
                orchestrator=orchestrator,
                scan_id=scan.id,
                target_url=request.target_url,
                categories=request.categories,
                max_concurrency=request.max_concurrency,
                timeout_seconds=request.timeout_seconds,
                external_authorized=request.external_target_authorized,
                http_client=http_client,
                enable_mutation_fuzzing=request.enable_mutation_fuzzing,
                mutation_types=request.mutation_types,
            )
        return scan

    @staticmethod
    def cancel_scan(
        db: Session,
        scan_id: str,
        user_id: str = "default_user",
        reason: str = "Cancelled by user",
    ) -> Scan:
        """Cancel a running or queued scan under authorized user identity."""
        scan = ScanRepository.get_scan(db, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan with ID '{scan_id}' not found.")

        # Check ownership if associated with a project
        if scan.project and scan.project.owner_id != user_id and scan.user_id != user_id:
            raise HTTPException(status_code=403, detail="Access denied: you do not own this scan.")

        if scan.status in ("COMPLETED", "FAILED", "CANCELLED"):
            return scan

        cancelled = ScanRepository.cancel_scan(db, scan_id=scan_id, reason=reason)
        ScanEventService.publish_event(
            scan_id=scan_id,
            event_type=ScanEventType.SCAN_CANCELLED.value,
            payload={"reason": reason},
            db=db,
            persist=True,
        )
        return cancelled

    @staticmethod
    def get_scan(db: Session, scan_id: str, user_id: Optional[str] = None) -> Scan:
        """Retrieve scan record or raise 404."""
        scan = ScanRepository.get_scan(db, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan with ID '{scan_id}' not found.")
        if user_id and scan.project and scan.project.owner_id != user_id and scan.user_id != user_id:
            raise HTTPException(status_code=403, detail="Access denied: you do not own this scan.")
        return scan

    @staticmethod
    def list_scans(db: Session, skip: int = 0, limit: int = 50) -> List[Scan]:
        """Fetch paginated scan records."""
        return ScanRepository.list_scans(db, skip=skip, limit=limit)

    @staticmethod
    def list_project_scans(
        db: Session,
        project_id: str,
        user_id: str = "default_user",
        skip: int = 0,
        limit: int = 50,
        status: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Fetch paginated scans for a project with ownership validation."""
        project = ProjectRepository.get_project(db, project_id=project_id, owner_id=user_id)
        if not project:
            raise HTTPException(status_code=404, detail=f"Project '{project_id}' not found.")

        items = ScanRepository.list_scans_by_project(
            db=db, project_id=project_id, skip=skip, limit=limit, status=status
        )
        total = ScanRepository.count_scans_by_project(db=db, project_id=project_id, status=status)
        return {"total": total, "items": items}

    @staticmethod
    def get_scan_test_executions(
        db: Session,
        scan_id: str,
        user_id: Optional[str] = None,
        skip: int = 0,
        limit: int = 100,
        status: Optional[str] = None,
        category: Optional[str] = None,
    ) -> TestExecutionListResponse:
        """Retrieve paginated test execution records for a scan."""
        # Ensure scan exists and user is authorized
        ScanService.get_scan(db, scan_id, user_id=user_id)

        items = TestExecutionRepository.list_executions_by_scan(
            db=db, scan_id=scan_id, status=status, category=category, skip=skip, limit=limit
        )
        total = TestExecutionRepository.count_executions_by_scan(
            db=db, scan_id=scan_id, status=status, category=category
        )

        response_items = []
        for it in items:
            response_items.append(
                TestExecutionResponse(
                    id=it.id,
                    scan_id=it.scan_id,
                    test_case_id=it.test_case_id,
                    category=it.category,
                    test_version=it.test_version,
                    input_fixture=it.input_fixture,
                    expected_behavior=it.expected_behavior,
                    observed_behavior=it.observed_behavior,
                    execution_status=it.execution_status,
                    latency_ms=it.latency_ms,
                    response_status=it.response_status,
                    detection_result=it.detection_result or {},
                    evidence=it.evidence or {},
                    error_message=it.error_message,
                    started_at=it.started_at.isoformat() if it.started_at else None,
                    completed_at=it.completed_at.isoformat() if it.completed_at else None,
                )
            )

        return TestExecutionListResponse(total=total, items=response_items)

    @staticmethod
    def get_findings_for_scan(
        db: Session,
        scan_id: str,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> List[Finding]:
        """Retrieve findings associated with a scan."""
        ScanService.get_scan(db, scan_id, user_id=user_id)
        return FindingRepository.list_findings_by_scan(
            db, scan_id=scan_id, category=category, severity=severity
        )

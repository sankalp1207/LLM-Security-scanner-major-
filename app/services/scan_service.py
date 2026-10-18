"""Service orchestrating scan creation, execution, and history retrieval."""

from typing import Any, List, Optional

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.database.models import Finding, Scan
from app.database.repository import FindingRepository, ScanRepository
from app.scanner.orchestrator import ScanOrchestrator
from app.scanner.target_client import TargetClient
from app.schemas.scans import ScanCreateRequest


class ScanService:
    """Business logic for scan management."""

    @staticmethod
    def create_and_run_scan(
        db: Session,
        request: ScanCreateRequest,
        http_client: Any = None,
        sync_execute: bool = True,
    ) -> Scan:
        """Validate, persist, and execute a security scan."""
        # 1. Target authorization validation
        validation = TargetClient.validate_target(
            target_url=request.target_url,
            external_authorized=request.external_target_authorized,
        )
        if not validation.is_valid:
            raise HTTPException(status_code=400, detail=validation.error_message)

        # 2. Persist initial scan record
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
        )

        # 3. Execute orchestrator
        if http_client is None and "testserver" in request.target_url:
            from httpx import ASGITransport, AsyncClient

            from app.main import app
            http_client = AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver")

        if sync_execute:
            orchestrator = ScanOrchestrator(db=db)
            import asyncio
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            if loop.is_running():
                # If running inside an existing event loop, create task or return
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    def _run():
                        new_loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(new_loop)
                        return new_loop.run_until_complete(
                            orchestrator.execute_scan(
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
                        )
                    scan = executor.submit(_run).result()
            else:
                scan = loop.run_until_complete(
                    orchestrator.execute_scan(
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
                )

        return scan

    @staticmethod
    def get_scan(db: Session, scan_id: str) -> Scan:
        """Retrieve scan record or raise 404."""
        scan = ScanRepository.get_scan(db, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan with ID '{scan_id}' not found.")
        return scan

    @staticmethod
    def list_scans(db: Session, skip: int = 0, limit: int = 50) -> List[Scan]:
        """Fetch paginated scan records."""
        return ScanRepository.list_scans(db, skip=skip, limit=limit)

    @staticmethod
    def get_findings_for_scan(
        db: Session,
        scan_id: str,
        category: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Finding]:
        """Retrieve findings associated with a scan."""
        # Ensure scan exists
        ScanService.get_scan(db, scan_id)
        return FindingRepository.list_findings_by_scan(
            db, scan_id=scan_id, category=category, severity=severity
        )

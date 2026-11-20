"""Service managing vulnerability finding review, details, and remediation retesting."""

import asyncio
from typing import Any, Dict, Optional

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.database.models import Finding
from app.database.repository import FindingRepository, ScanRepository
from app.detectors.data_leakage import DataLeakageDetector
from app.detectors.prompt_injection import PromptInjectionDetector
from app.scanner.target_client import TargetClient


class FindingService:
    """Business logic for finding inspection and remediation retesting."""

    @staticmethod
    def list_findings(
        db: Session,
        skip: int = 0,
        limit: int = 50,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        retest_status: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> list[Finding]:
        """Retrieve paginated findings across all scans with optional filters."""
        return FindingRepository.list_all_findings(
            db=db,
            skip=skip,
            limit=limit,
            category=category,
            severity=severity,
            retest_status=retest_status,
            user_id=user_id,
        )

    @staticmethod
    def get_finding(db: Session, finding_id: str, user_id: Optional[str] = None) -> Finding:
        """Fetch finding by ID or raise 404."""
        finding = FindingRepository.get_finding(db, finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail=f"Finding with ID '{finding_id}' not found.")
        if user_id is not None:
            scan = ScanRepository.get_scan(db, finding.scan_id)
            if not scan or scan.user_id != user_id:
                raise HTTPException(status_code=404, detail=f"Finding with ID '{finding_id}' not found.")
        return finding

    @staticmethod
    def retest_finding(
        db: Session,
        finding_id: str,
        user_id: Optional[str] = None,
        http_client: Any = None,
    ) -> Dict[str, Any]:
        """Retest a specific vulnerability against the target to verify if mitigation resolved it."""
        finding = FindingService.get_finding(db, finding_id, user_id=user_id)
        scan = ScanRepository.get_scan(db, finding.scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Parent scan record not found.")

        target_url = scan.target_identifier
        scan_config = scan.configuration_snapshot or scan.configuration or {}
        external_authorized = bool(
            scan_config.get("external_authorized")
            or scan_config.get("external_target_authorized")
        )
        destination = TargetClient.validate_target(
            target_url, external_authorized=external_authorized
        )
        if not destination.is_valid:
            FindingRepository.update_retest_status(
                db, finding_id=finding.id, retest_status="RETEST_INCONCLUSIVE"
            )
            return {
                "finding_id": finding.id,
                "retest_status": "RETEST_INCONCLUSIVE",
                "message": f"Retest blocked by target safety validation: {destination.error_message}",
                "response_status": None,
                "response_snippet": "",
            }
        test_case_id = finding.affected_test_case

        # Extract input text from evidence
        input_text = finding.evidence.get("input_snippet", "")
        if not input_text:
            input_text = finding.title

        if http_client is None and "testserver" in target_url:
            from httpx import ASGITransport, AsyncClient

            from app.main import app
            http_client = AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver")

        # Execute single test request
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                def _run():
                    new_loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(new_loop)
                    return new_loop.run_until_complete(
                        TargetClient.execute_test(
                            target_url=target_url,
                            test_case_id=test_case_id,
                            category=finding.category,
                            input_text=input_text,
                            client=http_client,
                        )
                    )
                exec_res = executor.submit(_run).result()
        else:
            exec_res = loop.run_until_complete(
                TargetClient.execute_test(
                    target_url=target_url,
                    test_case_id=test_case_id,
                    category=finding.category,
                    input_text=input_text,
                    client=http_client,
                )
            )

        # Re-evaluate with detector
        if "prompt_injection" in finding.category:
            recheck = PromptInjectionDetector.analyze(
                input_text=exec_res.input_text,
                response_text=exec_res.response_text,
            )
        else:
            recheck = DataLeakageDetector.analyze(
                input_text=exec_res.input_text,
                response_text=exec_res.response_text,
            )

        # A missing, failed, or non-success response cannot prove the vulnerability is fixed.
        if (
            exec_res.is_inconclusive
            or exec_res.error
            or exec_res.response_status is None
            or not 200 <= exec_res.response_status < 300
        ):
            new_status = "RETEST_INCONCLUSIVE"
            message = "Retest was inconclusive because the target did not return a successful, usable response."
        elif not recheck.exploit_verified:
            # Vulnerability has been mitigated!
            new_status = "RETEST_PASSED"
            message = "Remediation verified: test re-executed and vulnerability was no longer observed."
        else:
            new_status = "RETEST_FAILED"
            message = "Vulnerability still active: exploit was successfully reproduced during retest."

        FindingRepository.update_retest_status(db, finding_id=finding.id, retest_status=new_status)

        return {
            "finding_id": finding.id,
            "retest_status": new_status,
            "message": message,
            "response_status": exec_res.response_status,
            "response_snippet": (exec_res.response_text or "")[:200],
        }

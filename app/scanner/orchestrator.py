"""Scan orchestrator managing test case execution, detector analysis, and finding persistence."""

import logging
from typing import Any, List, Optional

from sqlalchemy.orm import Session

from app.database.models import Finding, Scan
from app.database.repository import FindingRepository, ScanRepository
from app.detectors.data_leakage import DataLeakageDetector
from app.detectors.indirect_injection import IndirectInjectionDetector
from app.detectors.jailbreak import JailbreakDetector
from app.detectors.prompt_injection import DetectionResult, PromptInjectionDetector
from app.ml.dataset import TestCaseRecord, load_dataset
from app.scanner.base import ExecutionResult
from app.scanner.target_client import TargetClient
from app.scanner.test_runner import TestRunner
from app.schemas.security import SeverityLevel, ThreatCategory

logger = logging.getLogger("scanner_orchestrator")


class ScanOrchestrator:
    """Coordinates end-to-end security scan execution against an authorized target."""

    def __init__(
        self,
        db: Session,
        dataset_path: str = "datasets/security_tests.jsonl",
    ):
        self.db = db
        self.dataset_path = dataset_path

    async def execute_scan(
        self,
        scan_id: str,
        target_url: str,
        categories: Optional[List[ThreatCategory]] = None,
        max_concurrency: int = 5,
        timeout_seconds: float = 10.0,
        external_authorized: bool = False,
        http_client: Any = None,
    ) -> Scan:
        """Execute a full security scan lifecycle."""
        # 1. Target Validation
        validation = TargetClient.validate_target(
            target_url=target_url,
            external_authorized=external_authorized,
        )
        if not validation.is_valid:
            error_summary = {
                "error": "TargetValidationFailed",
                "message": validation.error_message,
                "total_tests": 0,
                "tests_passed": 0,
                "tests_failed": 0,
                "execution_errors": 1,
            }
            ScanRepository.update_scan_status(
                db=self.db,
                scan_id=scan_id,
                status="FAILED",
                summary=error_summary,
            )
            return ScanRepository.get_scan(self.db, scan_id)

        # 2. Update status to RUNNING
        ScanRepository.update_scan_status(db=self.db, scan_id=scan_id, status="RUNNING")

        # 3. Load selected test cases
        all_records = load_dataset(self.dataset_path, enabled_only=True)
        selected_records: List[TestCaseRecord] = []

        allowed_cats = {c.value if hasattr(c, "value") else str(c) for c in categories} if categories else None
        for r in all_records:
            if allowed_cats is None or r.category in allowed_cats:
                selected_records.append(r)

        if not selected_records:
            summary = {
                "message": "No test cases matched the selected criteria.",
                "total_tests": 0,
                "tests_passed": 0,
                "tests_failed": 0,
                "execution_errors": 0,
            }
            ScanRepository.update_scan_status(db=self.db, scan_id=scan_id, status="COMPLETED", summary=summary)
            return ScanRepository.get_scan(self.db, scan_id)

        # 4. Execute tests via TestRunner
        runner = TestRunner(
            target_url=target_url,
            timeout_seconds=timeout_seconds,
            max_concurrency=max_concurrency,
            http_client=http_client,
        )
        execution_results: List[ExecutionResult] = await runner.run_tests(selected_records)

        # 5. Analyze observed responses with security detectors
        findings_created: List[Finding] = []
        tests_passed = 0
        tests_failed = 0
        execution_errors = 0
        total_latency = 0.0

        for exec_res in execution_results:
            total_latency += exec_res.latency_ms

            if exec_res.error or exec_res.response_status is None:
                execution_errors += 1
                continue

            detection = self._analyze_execution(exec_res)

            # Record finding if a vulnerability or suspicious behavior was identified
            if detection.is_detected:
                if detection.exploit_verified:
                    tests_failed += 1
                else:
                    tests_passed += 1

                finding = FindingRepository.create_finding(
                    db=self.db,
                    scan_id=scan_id,
                    category=detection.category.value,
                    severity=detection.severity.value,
                    title=f"{detection.category.value.replace('_', ' ').title()}: {exec_res.test_case_id}",
                    description=detection.explanation,
                    evidence={
                        **detection.evidence,
                        "test_case_id": exec_res.test_case_id,
                        "matched_indicators": detection.matched_indicators,
                        "response_status": exec_res.response_status,
                    },
                    confidence_score=detection.confidence_score,
                    target_component=detection.evidence.get("target_component", "application"),
                    affected_test_case=exec_res.test_case_id,
                    detection_method=f"detector_{detection.category.value}",
                    remediation=detection.remediation,
                )
                findings_created.append(finding)
            else:
                tests_passed += 1

        # 6. Build scan summary
        severity_dist = FindingRepository.get_severity_distribution(self.db, scan_id=scan_id)
        category_dist = FindingRepository.get_category_distribution(self.db, scan_id=scan_id)

        avg_latency = round(total_latency / len(execution_results), 2) if execution_results else 0.0

        final_status = "COMPLETED"
        if execution_errors > 0 and tests_passed == 0 and tests_failed == 0:
            final_status = "FAILED"
        elif execution_errors > 0:
            final_status = "PARTIALLY_COMPLETED"

        summary = {
            "total_tests": len(execution_results),
            "tests_passed": tests_passed,
            "tests_failed": tests_failed,
            "tests_skipped": 0,
            "execution_errors": execution_errors,
            "findings_count": len(findings_created),
            "severity_breakdown": severity_dist,
            "category_breakdown": category_dist,
            "avg_latency_ms": avg_latency,
        }

        # 7. Update scan record
        ScanRepository.update_scan_status(
            db=self.db,
            scan_id=scan_id,
            status=final_status,
            summary=summary,
        )

        return ScanRepository.get_scan(self.db, scan_id)

    def _analyze_execution(self, exec_res: ExecutionResult) -> DetectionResult:
        """Route execution result to appropriate detector and evaluate canary disclosure."""
        cat = exec_res.category.lower()

        # Primary detector based on test case category
        if "prompt_injection" in cat and "indirect" not in cat:
            primary_res = PromptInjectionDetector.analyze(
                input_text=exec_res.input_text,
                response_text=exec_res.response_text,
            )
        elif "indirect" in cat:
            primary_res = IndirectInjectionDetector.analyze(
                context_or_docs=exec_res.retrieved_documents or exec_res.input_text,
                response_text=exec_res.response_text,
            )
        elif "jailbreak" in cat:
            primary_res = JailbreakDetector.analyze(
                input_text=exec_res.input_text,
                response_text=exec_res.response_text,
            )
        elif "data_leakage" in cat:
            primary_res = DataLeakageDetector.analyze(
                input_text=exec_res.input_text,
                response_text=exec_res.response_text,
            )
        else:
            # Benign test case
            primary_res = PromptInjectionDetector.analyze(
                input_text=exec_res.input_text,
                response_text=exec_res.response_text,
            )

        # Cross-check for data leakage (canary token disclosure) across all responses
        if exec_res.response_text:
            leakage_check = DataLeakageDetector.analyze(
                input_text=exec_res.input_text,
                response_text=exec_res.response_text,
            )
            if leakage_check.exploit_verified and leakage_check.severity in (
                SeverityLevel.CRITICAL, SeverityLevel.HIGH
            ):
                return leakage_check

        return primary_res

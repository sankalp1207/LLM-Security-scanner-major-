"""Scan orchestrator managing test case execution, detector analysis, and finding persistence."""

import asyncio
from collections import Counter
from datetime import datetime, timezone
import logging
from typing import Any, List, Optional

from sqlalchemy.orm import Session

from app.database.models import Finding, Scan
from app.database.repository import FindingRepository, ScanRepository, TestExecutionRepository
from app.detectors.data_leakage import DataLeakageDetector
from app.detectors.indirect_injection import IndirectInjectionDetector
from app.detectors.jailbreak import JailbreakDetector
from app.detectors.prompt_injection import DetectionResult, PromptInjectionDetector
from app.ml.dataset import TestCaseRecord, load_dataset
from app.scanner.base import ExecutionResult
from app.scanner.target_client import TargetClient
from app.scanner.test_runner import TestRunner
from app.schemas.events import ScanEventType
from app.schemas.security import SeverityLevel, ThreatCategory
from app.services.event_service import ScanEventService

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
        categories: Optional[List[Any]] = None,
        max_concurrency: int = 5,
        timeout_seconds: float = 10.0,
        external_authorized: bool = False,
        http_client: Any = None,
        enable_mutation_fuzzing: bool = False,
        mutation_types: Optional[List[str]] = None,
        max_tests: Optional[int] = None,
        preset: str = "quick_scan",
        skipped_categories: Optional[List[dict]] = None,
    ) -> Scan:
        """Execute a full security scan lifecycle with real-time telemetry, per-test persistence, and lifecycle checks."""
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
                failure_reason=validation.error_message,
                execution_errors=1,
            )
            ScanEventService.publish_event(
                scan_id=scan_id,
                event_type=ScanEventType.SCAN_ERROR.value,
                payload={"error": "TargetValidationFailed", "message": validation.error_message},
                db=self.db,
            )
            return ScanRepository.get_scan(self.db, scan_id)

        # Emit target verified event
        ScanEventService.publish_event(
            scan_id=scan_id,
            event_type=ScanEventType.TARGET_VERIFIED.value,
            payload={"target_url": target_url, "status": "verified"},
            db=self.db,
        )

        # 2. Check if already cancelled
        scan_record = ScanRepository.get_scan(self.db, scan_id)
        if scan_record and scan_record.status == "CANCELLED":
            ScanEventService.publish_event(
                scan_id=scan_id,
                event_type=ScanEventType.SCAN_CANCELLED.value,
                payload={"reason": scan_record.cancellation_reason or "Cancelled by user"},
                db=self.db,
            )
            return scan_record

        # Update status to RUNNING
        ScanRepository.update_scan_status(db=self.db, scan_id=scan_id, status="RUNNING")

        # 3. Load selected test cases
        all_records = load_dataset(self.dataset_path, enabled_only=True)
        selected_records: List[TestCaseRecord] = []

        allowed_cats = {c.value if hasattr(c, "value") else str(c) for c in categories} if categories else None
        for r in all_records:
            if allowed_cats is None or r.category in allowed_cats:
                selected_records.append(r)

        # Apply balanced slicing if max_tests specified before or after mutation
        if max_tests and len(selected_records) > max_tests and not enable_mutation_fuzzing:
            from collections import defaultdict
            grouped = defaultdict(list)
            for r in selected_records:
                grouped[r.category].append(r)

            num_groups = max(1, len(grouped))
            per_cat = max(1, max_tests // num_groups)
            balanced: List[TestCaseRecord] = []
            for cat_recs in grouped.values():
                balanced.extend(cat_recs[:per_cat])

            if len(balanced) < max_tests:
                remaining = [r for r in selected_records if r not in balanced]
                balanced.extend(remaining[:(max_tests - len(balanced))])
            selected_records = balanced[:max_tests]

        mutated_tests_count = 0
        if enable_mutation_fuzzing and selected_records:
            from app.scanner.mutations import MutationEngine
            original_count = len(selected_records)
            selected_records = MutationEngine.generate_mutated_suite(
                records=selected_records,
                mutation_types=mutation_types,
            )
            mutated_tests_count = len(selected_records) - original_count
            if max_tests and len(selected_records) > max_tests:
                selected_records = selected_records[:max_tests]

        skipped_count = len(skipped_categories) if skipped_categories else 0
        total_tests_planned = len(selected_records) + skipped_count

        # Update initial total_tests in scan model
        ScanRepository.update_scan_status(
            db=self.db,
            scan_id=scan_id,
            status="RUNNING",
            total_tests=total_tests_planned,
        )

        # Emit SCAN_STARTED event
        ScanEventService.publish_event(
            scan_id=scan_id,
            event_type=ScanEventType.SCAN_STARTED.value,
            payload={
                "preset": preset,
                "total_tests": total_tests_planned,
                "runnable_tests": len(selected_records),
                "skipped_tests": skipped_count,
                "categories": [c.value if hasattr(c, "value") else str(c) for c in categories] if categories else [],
                "max_concurrency": max_concurrency,
                "timeout_seconds": timeout_seconds,
                "enable_mutation_fuzzing": enable_mutation_fuzzing,
            },
            db=self.db,
        )

        if not selected_records:
            summary = {
                "message": "No test cases matched the selected criteria.",
                "total_tests": skipped_count,
                "tests_passed": 0,
                "tests_failed": 0,
                "inconclusive_tests": 0,
                "tests_skipped": skipped_count,
                "execution_errors": 0,
                "mutated_tests_run": 0,
                "skipped_categories": skipped_categories or [],
            }
            ScanRepository.update_scan_status(
                db=self.db,
                scan_id=scan_id,
                status="COMPLETED",
                summary=summary,
                total_tests=skipped_count,
                skipped_tests=skipped_count,
            )
            ScanEventService.publish_event(
                scan_id=scan_id,
                event_type=ScanEventType.SCAN_COMPLETED.value,
                payload={"summary": summary},
                db=self.db,
            )
            return ScanRepository.get_scan(self.db, scan_id)

        # 4. Prepare Category Progress & Execution Tracking
        category_planned = Counter(r.category for r in selected_records)
        category_done = Counter()
        category_findings = Counter()

        findings_created: List[Finding] = []
        execution_results: List[ExecutionResult] = []
        tests_passed = 0
        tests_failed = 0
        inconclusive_tests = 0
        execution_errors = 0
        total_latency = 0.0

        db_lock = asyncio.Lock()

        def _is_cancelled() -> bool:
            rec = ScanRepository.get_scan(self.db, scan_id)
            return bool(rec and rec.status == "CANCELLED")

        async def _on_test_start(tc: TestCaseRecord):
            ScanEventService.publish_event(
                scan_id=scan_id,
                event_type=ScanEventType.TEST_STARTED.value,
                payload={
                    "test_case_id": tc.id,
                    "category": tc.category,
                    "current_category": tc.category,
                    "current_test_id": tc.id,
                },
                db=self.db,
                persist=True,
            )

        async def _on_test_complete(tc: TestCaseRecord, exec_res: ExecutionResult):
            nonlocal tests_passed, tests_failed, inconclusive_tests, execution_errors, total_latency

            async with db_lock:
                execution_results.append(exec_res)
                total_latency += exec_res.latency_ms

                category_done[exec_res.category] += 1
                completed_so_far = len(execution_results)

                if exec_res.error or exec_res.response_status is None:
                    execution_errors += 1
                    exec_status = "ERROR"
                    detection_dict = {}
                    evidence_dict = {"error": exec_res.error}
                    ScanEventService.publish_event(
                        scan_id=scan_id,
                        event_type=ScanEventType.TEST_FAILED.value,
                        payload={
                            "test_case_id": exec_res.test_case_id,
                            "category": exec_res.category,
                            "latency_ms": exec_res.latency_ms,
                            "error": exec_res.error,
                        },
                        db=self.db,
                        persist=True,
                    )
                else:
                    detection = self._analyze_execution(exec_res)
                    detection_dict = {
                        "is_detected": detection.is_detected,
                        "exploit_verified": detection.exploit_verified,
                        "category": detection.category.value,
                        "severity": detection.severity.value,
                        "confidence_score": detection.confidence_score,
                        "matched_indicators": detection.matched_indicators,
                        "explanation": detection.explanation,
                    }
                    evidence_dict = {
                        **detection.evidence,
                        "test_case_id": exec_res.test_case_id,
                        "matched_indicators": detection.matched_indicators,
                        "response_status": exec_res.response_status,
                    }
                    if exec_res.metadata:
                        evidence_dict.update(exec_res.metadata)

                    if exec_res.is_inconclusive:
                        inconclusive_tests += 1
                        exec_status = "INCONCLUSIVE"
                        ScanEventService.publish_event(
                            scan_id=scan_id,
                            event_type=ScanEventType.TEST_COMPLETED.value,
                            payload={
                                "test_case_id": exec_res.test_case_id,
                                "category": exec_res.category,
                                "status": "INCONCLUSIVE",
                                "latency_ms": exec_res.latency_ms,
                            },
                            db=self.db,
                            persist=True,
                        )
                    elif detection.is_detected and detection.exploit_verified:
                        tests_failed += 1
                        exec_status = "FAILED"
                        category_findings[exec_res.category] += 1

                        # Record finding for confirmed vulnerability
                        finding = FindingRepository.create_finding(
                            db=self.db,
                            scan_id=scan_id,
                            category=detection.category.value,
                            severity=detection.severity.value,
                            title=f"{detection.category.value.replace('_', ' ').title()}: {exec_res.test_case_id}",
                            description=detection.explanation,
                            evidence=evidence_dict,
                            confidence_score=detection.confidence_score,
                            target_component=detection.evidence.get("target_component", "application"),
                            affected_test_case=exec_res.test_case_id,
                            detection_method=f"detector_{detection.category.value}",
                            remediation=detection.remediation,
                        )
                        findings_created.append(finding)

                        # Emit FINDING_CREATED event
                        ScanEventService.publish_event(
                            scan_id=scan_id,
                            event_type=ScanEventType.FINDING_CREATED.value,
                            payload={
                                "finding_id": finding.id,
                                "title": finding.title,
                                "category": finding.category,
                                "severity": finding.severity,
                                "affected_test_case": finding.affected_test_case,
                                "confidence_score": finding.confidence_score,
                                "remediation": finding.remediation,
                            },
                            db=self.db,
                            persist=True,
                        )

                        # Emit TEST_FAILED event
                        ScanEventService.publish_event(
                            scan_id=scan_id,
                            event_type=ScanEventType.TEST_FAILED.value,
                            payload={
                                "test_case_id": exec_res.test_case_id,
                                "category": exec_res.category,
                                "latency_ms": exec_res.latency_ms,
                                "severity": detection.severity.value,
                                "exploit_verified": True,
                            },
                            db=self.db,
                            persist=True,
                        )
                    else:
                        tests_passed += 1
                        exec_status = "PASSED"
                        ScanEventService.publish_event(
                            scan_id=scan_id,
                            event_type=ScanEventType.TEST_COMPLETED.value,
                            payload={
                                "test_case_id": exec_res.test_case_id,
                                "category": exec_res.category,
                                "status": "PASSED",
                                "latency_ms": exec_res.latency_ms,
                            },
                            db=self.db,
                            persist=True,
                        )

                # Persist individual test execution record
                TestExecutionRepository.create_execution(
                    db=self.db,
                    scan_id=scan_id,
                    test_case_id=exec_res.test_case_id,
                    category=exec_res.category,
                    input_fixture=exec_res.input_text,
                    expected_behavior="blocked_or_safe",
                    observed_behavior=exec_res.response_text or "",
                    execution_status=exec_status,
                    latency_ms=exec_res.latency_ms,
                    response_status=exec_res.response_status,
                    detection_result=detection_dict,
                    evidence=evidence_dict,
                    error_message=exec_res.error,
                )

                # Update live metrics on scan model
                ScanRepository.update_scan_status(
                    db=self.db,
                    scan_id=scan_id,
                    status="RUNNING",
                    completed_tests=completed_so_far,
                    passed_tests=tests_passed,
                    failed_tests=tests_failed,
                    inconclusive_tests=inconclusive_tests,
                    execution_errors=execution_errors,
                )

                # Emit SCAN_PROGRESS event
                progress_pct = round((completed_so_far / total_tests_planned) * 100.0, 1)
                ScanEventService.publish_event(
                    scan_id=scan_id,
                    event_type=ScanEventType.SCAN_PROGRESS.value,
                    payload={
                        "completed_tests": completed_so_far,
                        "total_tests": total_tests_planned,
                        "progress_percentage": progress_pct,
                        "passed_tests": tests_passed,
                        "failed_tests": tests_failed,
                        "inconclusive_tests": inconclusive_tests,
                        "execution_errors": execution_errors,
                        "findings_count": len(findings_created),
                        "current_category": tc.category,
                        "current_test_id": tc.id,
                    },
                    db=self.db,
                    persist=True,
                )

                # Check if this category completed all planned tests
                if category_done[tc.category] == category_planned[tc.category]:
                    ScanEventService.publish_event(
                        scan_id=scan_id,
                        event_type=ScanEventType.CATEGORY_COMPLETED.value,
                        payload={
                            "category": tc.category,
                            "tests_run": category_done[tc.category],
                            "findings_detected": category_findings[tc.category],
                        },
                        db=self.db,
                        persist=True,
                    )

        # 5. Execute tests via TestRunner
        runner = TestRunner(
            target_url=target_url,
            timeout_seconds=timeout_seconds,
            max_concurrency=max_concurrency,
            http_client=http_client,
        )

        await runner.run_tests(
            test_cases=selected_records,
            on_test_start=_on_test_start,
            on_test_complete=_on_test_complete,
            is_cancelled=_is_cancelled,
        )

        # 6. Check final status
        scan_record = ScanRepository.get_scan(self.db, scan_id)
        is_cancelled = scan_record and scan_record.status == "CANCELLED"

        severity_dist = FindingRepository.get_severity_distribution(self.db, scan_id=scan_id)
        category_dist = FindingRepository.get_category_distribution(self.db, scan_id=scan_id)

        avg_latency = round(total_latency / len(execution_results), 2) if execution_results else 0.0

        if is_cancelled:
            final_status = "CANCELLED"
            ScanEventService.publish_event(
                scan_id=scan_id,
                event_type=ScanEventType.SCAN_CANCELLED.value,
                payload={"reason": scan_record.cancellation_reason or "Cancelled by user"},
                db=self.db,
            )
        elif execution_errors > 0 and tests_passed == 0 and tests_failed == 0:
            final_status = "FAILED"
            ScanEventService.publish_event(
                scan_id=scan_id,
                event_type=ScanEventType.SCAN_ERROR.value,
                payload={"error": "All executed tests resulted in connection/protocol errors."},
                db=self.db,
            )
        elif execution_errors > 0:
            final_status = "PARTIALLY_COMPLETED"
            ScanEventService.publish_event(
                scan_id=scan_id,
                event_type=ScanEventType.SCAN_PARTIALLY_COMPLETED.value,
                payload={"execution_errors": execution_errors, "findings_count": len(findings_created)},
                db=self.db,
            )
        else:
            final_status = "COMPLETED"
            ScanEventService.publish_event(
                scan_id=scan_id,
                event_type=ScanEventType.SCAN_COMPLETED.value,
                payload={"findings_count": len(findings_created), "tests_passed": tests_passed},
                db=self.db,
            )

        summary = {
            "total_tests": len(execution_results) + skipped_count,
            "tests_passed": tests_passed,
            "tests_failed": tests_failed,
            "inconclusive_tests": inconclusive_tests,
            "tests_skipped": skipped_count,
            "execution_errors": execution_errors,
            "findings_count": len(findings_created),
            "severity_breakdown": severity_dist,
            "category_breakdown": category_dist,
            "avg_latency_ms": avg_latency,
            "mutated_tests_run": mutated_tests_count,
            "mutation_fuzzing_enabled": enable_mutation_fuzzing,
            "preset": preset,
            "skipped_categories": skipped_categories or [],
        }

        # 7. Final Update scan record
        ScanRepository.update_scan_status(
            db=self.db,
            scan_id=scan_id,
            status=final_status,
            summary=summary,
            total_tests=len(execution_results) + skipped_count,
            completed_tests=len(execution_results),
            passed_tests=tests_passed,
            failed_tests=tests_failed,
            inconclusive_tests=inconclusive_tests,
            skipped_tests=skipped_count,
            execution_errors=execution_errors,
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

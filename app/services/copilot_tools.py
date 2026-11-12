"""Controlled, deterministic backend tools for AI Security Copilot with strict authorization boundaries."""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.database.models import Finding, Project, Scan, TestExecution
from app.database.repository import (
    EvaluationRepository,
    FindingRepository,
    ProjectRepository,
    ScanRepository,
    TestExecutionRepository,
)
from app.schemas.copilot import ScanComparisonResponse

logger = logging.getLogger("copilot_tools")


class CopilotToolAccessError(Exception):
    """Raised when authorization or resource ownership checks fail."""
    pass


class CopilotTools:
    """Deterministic security inspection tools callable by the AI Security Copilot."""

    @staticmethod
    def _validate_scan_ownership(scan: Any, user_id: str, error_message: str = "Access denied.") -> None:
        """Enforce tenant isolation on scan records with or without bound projects."""
        if not scan:
            return
        if scan.project and scan.project.owner_id == user_id:
            return
        if scan.user_id and scan.user_id == user_id:
            return
        raise CopilotToolAccessError(error_message)

    @staticmethod
    def get_project_summary(db: Session, project_id: str, user_id: str) -> Dict[str, Any]:
        """Retrieve high-level project metadata, application type, environment, and scan counts."""
        project = ProjectRepository.get_project(db, project_id=project_id, owner_id=user_id)
        if not project:
            # Check if project exists under another user to prevent unauthorized information disclosure
            exists = db.query(Project).filter(Project.id == project_id).first()
            if exists:
                raise CopilotToolAccessError("Access denied: You do not have permission to inspect this project.")
            raise CopilotToolAccessError(f"Project '{project_id}' not found.")

        tc = project.target_configuration
        target_info = {
            "target_type": project.target_type,
            "provider": tc.provider if tc else "unknown",
            "endpoint_url": tc.endpoint_url if tc else "not configured",
            "connection_status": tc.connection_status if tc else "UNVERIFIED",
        }

        total_scans = ScanRepository.count_scans_by_project(db, project_id=project.id)
        scans = ScanRepository.list_scans_by_project(db, project_id=project.id, limit=1)
        latest_scan = scans[0] if scans else None

        findings_count = 0
        if latest_scan:
            findings_count = len(FindingRepository.list_findings_by_scan(db, scan_id=latest_scan.id))

        return {
            "project_id": project.id,
            "name": project.name,
            "application_type": project.application_type,
            "environment": project.environment,
            "description": project.description,
            "target": target_info,
            "total_scans_executed": total_scans,
            "latest_scan_id": latest_scan.id if latest_scan else None,
            "latest_scan_status": latest_scan.status if latest_scan else None,
            "latest_findings_count": findings_count,
        }

    @staticmethod
    def get_latest_scan(db: Session, project_id: str, user_id: str) -> Dict[str, Any]:
        """Fetch the most recent scan record and telemetry summary for a project."""
        project = ProjectRepository.get_project(db, project_id=project_id, owner_id=user_id)
        if not project:
            raise CopilotToolAccessError("Project not found or unauthorized.")

        scans = ScanRepository.list_scans_by_project(db, project_id=project_id, limit=1)
        if not scans:
            return {"message": "No security scans have been executed for this project yet."}

        latest = scans[0]
        findings = FindingRepository.list_findings_by_scan(db, scan_id=latest.id)
        severity_dist = FindingRepository.get_severity_distribution(db, scan_id=latest.id)

        return {
            "scan_id": latest.id,
            "project_id": project.id,
            "preset": latest.preset,
            "status": latest.status,
            "start_time": latest.start_timestamp.isoformat() if latest.start_timestamp else None,
            "completion_time": latest.completion_timestamp.isoformat() if latest.completion_timestamp else None,
            "total_tests": latest.total_tests,
            "completed_tests": latest.completed_tests,
            "passed_tests": latest.passed_tests,
            "failed_tests": latest.failed_tests,
            "inconclusive_tests": latest.inconclusive_tests,
            "findings_count": len(findings),
            "severity_breakdown": severity_dist,
            "summary": latest.summary,
            "cancellation_reason": latest.cancellation_reason,
            "failure_reason": latest.failure_reason,
        }

    @staticmethod
    def get_scan_history(db: Session, project_id: str, user_id: str, limit: int = 5) -> List[Dict[str, Any]]:
        """List historical scan executions for a project."""
        project = ProjectRepository.get_project(db, project_id=project_id, owner_id=user_id)
        if not project:
            raise CopilotToolAccessError("Project not found or unauthorized.")

        safe_limit = max(1, min(limit, 10))
        scans = ScanRepository.list_scans_by_project(db, project_id=project_id, limit=safe_limit)
        results = []
        for s in scans:
            f_count = len(FindingRepository.list_findings_by_scan(db, scan_id=s.id))
            results.append({
                "scan_id": s.id,
                "preset": s.preset,
                "status": s.status,
                "total_tests": s.total_tests,
                "passed_tests": s.passed_tests,
                "failed_tests": s.failed_tests,
                "findings_count": f_count,
                "started_at": s.start_timestamp.isoformat() if s.start_timestamp else None,
                "completed_at": s.completion_timestamp.isoformat() if s.completion_timestamp else None,
            })
        return results

    @staticmethod
    def get_scan_details(db: Session, scan_id: str, user_id: str) -> Dict[str, Any]:
        """Fetch details, summary metrics, and configuration snapshot of a specific scan."""
        scan = ScanRepository.get_scan(db, scan_id=scan_id)
        if not scan:
            raise CopilotToolAccessError(f"Scan '{scan_id}' not found.")

        CopilotTools._validate_scan_ownership(
            scan, user_id, "Access denied: You do not have permission to inspect this scan."
        )

        findings = FindingRepository.list_findings_by_scan(db, scan_id=scan.id)
        severity_dist = FindingRepository.get_severity_distribution(db, scan_id=scan.id)

        config_safe = scan.configuration_snapshot or scan.configuration or {}

        return {
            "scan_id": scan.id,
            "project_id": scan.project_id,
            "preset": scan.preset,
            "status": scan.status,
            "target_identifier": scan.target_identifier,
            "start_timestamp": scan.start_timestamp.isoformat() if scan.start_timestamp else None,
            "completion_timestamp": scan.completion_timestamp.isoformat() if scan.completion_timestamp else None,
            "total_tests": scan.total_tests,
            "completed_tests": scan.completed_tests,
            "passed_tests": scan.passed_tests,
            "failed_tests": scan.failed_tests,
            "inconclusive_tests": scan.inconclusive_tests,
            "skipped_tests": scan.skipped_tests,
            "execution_errors": scan.execution_errors,
            "findings_count": len(findings),
            "severity_breakdown": severity_dist,
            "summary": scan.summary,
            "cancellation_reason": scan.cancellation_reason,
            "failure_reason": scan.failure_reason,
            "configuration": config_safe,
        }

    @staticmethod
    def get_scan_findings(
        db: Session,
        scan_id: str,
        user_id: str,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """Retrieve confirmed vulnerability findings identified in a scan."""
        scan = ScanRepository.get_scan(db, scan_id=scan_id)
        if not scan:
            raise CopilotToolAccessError(f"Scan '{scan_id}' not found.")

        CopilotTools._validate_scan_ownership(
            scan, user_id, "Access denied: You do not have permission to inspect findings for this scan."
        )

        safe_limit = max(1, min(limit, 50))
        findings = FindingRepository.list_findings_by_scan(
            db, scan_id=scan_id, category=category, severity=severity
        )[:safe_limit]

        results = []
        for f in findings:
            results.append({
                "finding_id": f.id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity,
                "description": f.description,
                "target_component": f.target_component,
                "affected_test_case": f.affected_test_case,
                "confidence_score": f.confidence_score,
                "retest_status": f.retest_status,
                "remediation": f.remediation,
            })
        return results

    @staticmethod
    def get_finding_details(db: Session, finding_id: str, user_id: str) -> Dict[str, Any]:
        """Fetch deep evidence, verification details, and remediation guidance for a specific finding."""
        finding = FindingRepository.get_finding(db, finding_id=finding_id)
        if not finding:
            raise CopilotToolAccessError(f"Finding with ID '{finding_id}' not found.")

        # Check project or scan ownership
        if finding.scan:
            CopilotTools._validate_scan_ownership(
                finding.scan, user_id, "Access denied: You do not own the project or scan containing this finding."
            )

        return {
            "finding_id": finding.id,
            "scan_id": finding.scan_id,
            "title": finding.title,
            "category": finding.category,
            "severity": finding.severity,
            "description": finding.description,
            "evidence": finding.evidence or {},
            "confidence_score": finding.confidence_score,
            "target_component": finding.target_component,
            "affected_test_case": finding.affected_test_case,
            "detection_method": finding.detection_method,
            "remediation": finding.remediation,
            "retest_status": finding.retest_status,
            "creation_timestamp": finding.creation_timestamp.isoformat() if finding.creation_timestamp else None,
        }

    @staticmethod
    def get_test_execution_details(
        db: Session,
        scan_id: str,
        test_case_id: str,
        user_id: str,
    ) -> Dict[str, Any]:
        """Retrieve observed execution telemetry and input/output payload for an individual test."""
        scan = ScanRepository.get_scan(db, scan_id=scan_id)
        if not scan:
            raise CopilotToolAccessError(f"Scan '{scan_id}' not found.")
        CopilotTools._validate_scan_ownership(scan, user_id, "Access denied.")

        executions = TestExecutionRepository.list_executions_by_scan(db, scan_id=scan_id, limit=200)
        matched = next((e for e in executions if e.test_case_id == test_case_id), None)
        if not matched:
            raise CopilotToolAccessError(f"Test case '{test_case_id}' was not executed in scan '{scan_id}'.")

        return {
            "execution_id": matched.id,
            "scan_id": matched.scan_id,
            "test_case_id": matched.test_case_id,
            "category": matched.category,
            "input_fixture": matched.input_fixture,
            "observed_behavior": matched.observed_behavior,
            "execution_status": matched.execution_status,
            "latency_ms": matched.latency_ms,
            "response_status": matched.response_status,
            "error_message": matched.error_message,
        }

    @staticmethod
    def compare_scans(
        db: Session,
        scan_id_a: str,
        scan_id_b: str,
        user_id: str,
    ) -> ScanComparisonResponse:
        """
        Compare two scans (Baseline A vs. Target B) to evaluate security posture evolution,
        newly introduced vulnerabilities, resolved issues, common finding shifts, and regressions.
        """
        scan_a = ScanRepository.get_scan(db, scan_id=scan_id_a)
        scan_b = ScanRepository.get_scan(db, scan_id=scan_id_b)

        if not scan_a:
            raise CopilotToolAccessError(f"Baseline scan '{scan_id_a}' not found.")
        if not scan_b:
            raise CopilotToolAccessError(f"Target scan '{scan_id_b}' not found.")

        # Check authorization for both scans
        for s in (scan_a, scan_b):
            CopilotTools._validate_scan_ownership(s, user_id, f"Access denied: You do not own scan '{s.id}'.")

        findings_a = FindingRepository.list_findings_by_scan(db, scan_id=scan_a.id)
        findings_b = FindingRepository.list_findings_by_scan(db, scan_id=scan_b.id)

        # Map findings by fingerprint (category + affected_test_case)
        def _fingerprint(f: Finding) -> str:
            return f"{f.category}:{f.affected_test_case or f.title}"

        map_a = {_fingerprint(f): f for f in findings_a}
        map_b = {_fingerprint(f): f for f in findings_b}

        new_keys = set(map_b.keys()) - set(map_a.keys())
        resolved_keys = set(map_a.keys()) - set(map_b.keys())
        common_keys = set(map_a.keys()) & set(map_b.keys())

        new_findings = [
            {
                "finding_id": map_b[k].id,
                "title": map_b[k].title,
                "category": map_b[k].category,
                "severity": map_b[k].severity,
            }
            for k in new_keys
        ]

        resolved_findings = [
            {
                "finding_id": map_a[k].id,
                "title": map_a[k].title,
                "category": map_a[k].category,
                "severity": map_a[k].severity,
            }
            for k in resolved_keys
        ]

        common_findings = []
        for k in common_keys:
            fa = map_a[k]
            fb = map_b[k]
            common_findings.append({
                "title": fb.title,
                "category": fb.category,
                "severity_in_a": fa.severity,
                "severity_in_b": fb.severity,
                "retest_status": fb.retest_status,
            })

        # Severity distributions
        sev_a = FindingRepository.get_severity_distribution(db, scan_id=scan_a.id)
        sev_b = FindingRepository.get_severity_distribution(db, scan_id=scan_b.id)
        sev_shift = {}
        for s_level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
            diff = sev_b.get(s_level, 0) - sev_a.get(s_level, 0)
            sev_shift[s_level] = diff

        # Coverage diff
        cov_diff = {
            "tests_in_a": scan_a.total_tests or 0,
            "tests_in_b": scan_b.total_tests or 0,
            "completed_in_a": scan_a.completed_tests or 0,
            "completed_in_b": scan_b.completed_tests or 0,
            "delta_tests": (scan_b.total_tests or 0) - (scan_a.total_tests or 0),
        }

        # Regression summary
        if len(new_findings) > 0:
            reg_summary = (
                f"⚠️ Security Regression Detected: Scan B introduced {len(new_findings)} new vulnerabilities "
                f"not observed in Scan A. {len(resolved_findings)} previous findings were resolved."
            )
        elif len(resolved_findings) > 0:
            reg_summary = (
                f"✅ Security Posture Improved: {len(resolved_findings)} vulnerabilities resolved with 0 new issues introduced."
            )
        else:
            reg_summary = f"⚖️ Security Posture Consistent: Identical vulnerability footprint between both scans."

        return ScanComparisonResponse(
            scan_id_a=scan_a.id,
            scan_id_b=scan_b.id,
            scan_a_date=scan_a.start_timestamp.isoformat() if scan_a.start_timestamp else "N/A",
            scan_b_date=scan_b.start_timestamp.isoformat() if scan_b.start_timestamp else "N/A",
            scan_a_preset=scan_a.preset or "quick_scan",
            scan_b_preset=scan_b.preset or "quick_scan",
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            common_findings=common_findings,
            severity_shift=sev_shift,
            coverage_diff=cov_diff,
            regression_summary=reg_summary,
        )

    @staticmethod
    def get_mitigation_history(db: Session, finding_id: str, user_id: str) -> Dict[str, Any]:
        """Fetch remediation guidance, retest outcome, and mitigation validation history."""
        finding = FindingRepository.get_finding(db, finding_id=finding_id)
        if not finding:
            raise CopilotToolAccessError(f"Finding '{finding_id}' not found.")

        if finding.scan:
            CopilotTools._validate_scan_ownership(finding.scan, user_id, "Access denied.")

        return {
            "finding_id": finding.id,
            "title": finding.title,
            "category": finding.category,
            "severity": finding.severity,
            "current_retest_status": finding.retest_status,
            "recommended_remediation": finding.remediation,
            "affected_component": finding.target_component,
            "detection_method": finding.detection_method,
        }

    @staticmethod
    def get_attack_path(db: Session, project_id: str, user_id: str) -> Dict[str, Any]:
        """Correlate active findings into a multi-stage attack execution chain for the project."""
        project = ProjectRepository.get_project(db, project_id=project_id, owner_id=user_id)
        if not project:
            raise CopilotToolAccessError("Project not found or unauthorized.")

        scans = ScanRepository.list_scans_by_project(db, project_id=project_id, limit=1)
        if not scans:
            return {"stages": {}, "total_vectors": 0, "summary": "No scans available to map attack paths."}

        latest_scan = scans[0]
        findings = FindingRepository.list_findings_by_scan(db, scan_id=latest_scan.id)

        # Group findings into 4 stages
        stage_1_evasion = [f.title for f in findings if "obfuscation" in f.category or "mutation" in f.category]
        stage_2_injection = [f.title for f in findings if f.category in ("prompt_injection", "jailbreak")]
        stage_3_poisoning = [f.title for f in findings if f.category == "indirect_prompt_injection"]
        stage_4_disclosure = [f.title for f in findings if f.category == "data_leakage"]

        return {
            "project_name": project.name,
            "scan_id": latest_scan.id,
            "total_findings": len(findings),
            "stages": {
                "Stage 1: Evasion & Encoding Obfuscation": stage_1_evasion,
                "Stage 2: Instruction Boundary Hijacking": stage_2_injection,
                "Stage 3: Untrusted Document Context Poisoning": stage_3_poisoning,
                "Stage 4: Sensitive Data Exfiltration / Canary Leak": stage_4_disclosure,
            },
            "summary": (
                f"Attack chain identified across {len(findings)} active findings in scan {latest_scan.id[:8]}."
            ),
        }

    @staticmethod
    def get_ml_evaluation(db: Session) -> Dict[str, Any]:
        """Fetch baseline threat classifier performance metrics, false positive rates, and evaluation limitations."""
        eval_record = EvaluationRepository.get_latest(db)
        if not eval_record:
            return {
                "status": "No evaluated model found",
                "message": "Train the baseline ML model with scripts/train_model.py to establish evaluation metrics.",
            }

        cm = eval_record.confusion_matrix or {}
        return {
            "model_version": eval_record.model_version,
            "dataset_version": eval_record.dataset_version,
            "precision": round(eval_record.precision, 4),
            "recall": round(eval_record.recall, 4),
            "f1_score": round(eval_record.f1_score, 4),
            "false_positive_rate": round(eval_record.false_positive_rate, 4),
            "false_negative_rate": round(eval_record.false_negative_rate, 4),
            "test_sample_count": eval_record.test_sample_count,
            "confusion_matrix": {
                "true_positives": cm.get("tp", 0),
                "true_negatives": cm.get("tn", 0),
                "false_positives": cm.get("fp", 0),
                "false_negatives": cm.get("fn", 0),
            },
            "known_limitations": [
                "Bag-of-words / TF-IDF representations may struggle with multi-hop reasoning attacks.",
                "Adversarial mutations (e.g. homoglyphs, deep base64 nesting) require normalizer de-obfuscation prior to classification.",
                "Supervised classifier probability scores must be supplemented with deterministic canary verification.",
            ],
        }

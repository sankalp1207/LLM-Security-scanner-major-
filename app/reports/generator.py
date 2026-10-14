"""Audit report generator creating structured summaries conforming to security reporting standards."""

from typing import Dict, List

from sqlalchemy.orm import Session

from app.database.repository import FindingRepository, ScanRepository
from app.schemas.reports import ScanReportResponse
from app.schemas.scans import FindingResponse


class ReportGenerator:
    """Generates structured security assessment reports."""

    EVALUATION_LIMITATIONS: List[str] = [
        "Evaluation is conducted using documented synthetic security test vectors. Production attack payloads may exhibit variations not captured in this test suite.",
        "Baseline threat classification uses TF-IDF and Logistic Regression. Novel adversarial semantics or advanced token-level encoding may evade statistical detection.",
        "Sensitive information leakage verification relies on predefined synthetic canary tokens and known credential patterns. Unstructured proprietary text disclosure requires manual contextual auditing.",
        "Retest verification reflects target defenses at the specific time of execution. Dynamic model changes, prompt modifications, or tool updates may cause regressions.",
    ]

    @classmethod
    def generate_report(cls, db: Session, scan_id: str) -> ScanReportResponse:
        """Construct full structured security report for a given scan."""
        scan = ScanRepository.get_scan(db, scan_id)
        if not scan:
            raise ValueError(f"Scan '{scan_id}' not found.")

        findings = FindingRepository.list_findings_by_scan(db, scan_id=scan.id)
        severity_dist = FindingRepository.get_severity_distribution(db, scan_id=scan.id)
        category_dist = FindingRepository.get_category_distribution(db, scan_id=scan.id)

        # Extract remediation recommendations
        remediations: List[Dict[str, str]] = []
        seen_remediations = set()
        for f in findings:
            if f.remediation and f.remediation not in seen_remediations:
                seen_remediations.add(f.remediation)
                remediations.append({
                    "category": f.category,
                    "severity": f.severity,
                    "recommendation": f.remediation,
                })

        summary_meta = scan.summary or {}

        summary_text = (
            f"Security scan executed against {scan.target_identifier} finished with status '{scan.status}'. "
            f"Evaluated {summary_meta.get('total_tests', 0)} total test cases with {summary_meta.get('tests_failed', 0)} "
            f"observed security failures and {len(findings)} identified findings."
        )

        finding_responses = [
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

        return ScanReportResponse(
            scan_id=scan.id,
            target_identifier=scan.target_identifier,
            scanner_version=scan.scanner_version,
            model_version="tfidf-logreg-v1",
            status=scan.status,
            start_time=scan.start_timestamp.isoformat(),
            completion_time=scan.completion_timestamp.isoformat() if scan.completion_timestamp else None,
            total_tests=summary_meta.get("total_tests", 0),
            tests_passed=summary_meta.get("tests_passed", 0),
            tests_failed=summary_meta.get("tests_failed", 0),
            tests_skipped=summary_meta.get("tests_skipped", 0),
            execution_errors=summary_meta.get("execution_errors", 0),
            findings_by_severity=severity_dist,
            findings_by_category=category_dist,
            findings=finding_responses,
            remediation_recommendations=remediations,
            evaluation_limitations=cls.EVALUATION_LIMITATIONS,
            summary=summary_text,
        )

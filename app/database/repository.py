"""Database repositories encapsulating persistence operations for the scanner."""

from datetime import datetime, timezone
from typing import Dict, List, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database.models import (
    Finding,
    ModelEvaluation,
    Scan,
    SecurityTestCase,
    TestSuiteVersion,
)


class ScanRepository:
    """Repository managing Scan model persistence."""

    @staticmethod
    def create_scan(
        db: Session,
        target_identifier: str,
        configuration: dict,
        scanner_version: str = "1.0.0",
        scan_id: Optional[str] = None,
    ) -> Scan:
        """Create and persist a new Scan record."""
        scan = Scan(
            id=scan_id or None,
            target_identifier=target_identifier,
            status="PENDING",
            configuration=configuration,
            start_timestamp=datetime.now(timezone.utc),
            summary={},
            scanner_version=scanner_version,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        return scan

    @staticmethod
    def get_scan(db: Session, scan_id: str) -> Optional[Scan]:
        """Retrieve a scan record by its ID."""
        return db.query(Scan).filter(Scan.id == scan_id).first()

    @staticmethod
    def list_scans(db: Session, skip: int = 0, limit: int = 20) -> List[Scan]:
        """Retrieve paginated list of scans ordered by start time descending."""
        return (
            db.query(Scan)
            .order_by(Scan.start_timestamp.desc())
            .offset(skip)
            .limit(limit)
            .all()
        )

    @staticmethod
    def count_scans(db: Session) -> int:
        """Return total count of scan records."""
        return db.query(func.count(Scan.id)).scalar() or 0

    @staticmethod
    def update_scan_status(
        db: Session,
        scan_id: str,
        status: str,
        summary: Optional[dict] = None,
    ) -> Optional[Scan]:
        """Update the status and summary of an existing scan."""
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return None
        scan.status = status
        if summary is not None:
            scan.summary = summary
        if status in ("COMPLETED", "FAILED", "CANCELLED", "PARTIALLY_COMPLETED"):
            scan.completion_timestamp = datetime.now(timezone.utc)
        db.commit()
        db.refresh(scan)
        return scan

    @staticmethod
    def delete_scan(db: Session, scan_id: str) -> bool:
        """Delete a scan and all associated findings."""
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return False
        db.delete(scan)
        db.commit()
        return True


class FindingRepository:
    """Repository managing Finding model persistence."""

    @staticmethod
    def create_finding(
        db: Session,
        scan_id: str,
        category: str,
        severity: str,
        title: str,
        description: str,
        evidence: dict,
        confidence_score: Optional[float] = None,
        target_component: str = "unknown",
        affected_test_case: str = "",
        detection_method: str = "",
        remediation: str = "",
        retest_status: str = "NOT_RETESTED",
    ) -> Finding:
        """Create and persist a security finding record."""
        finding = Finding(
            scan_id=scan_id,
            category=category,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            confidence_score=confidence_score,
            target_component=target_component,
            affected_test_case=affected_test_case,
            detection_method=detection_method,
            remediation=remediation,
            creation_timestamp=datetime.now(timezone.utc),
            retest_status=retest_status,
        )
        db.add(finding)
        db.commit()
        db.refresh(finding)
        return finding

    @staticmethod
    def list_findings_by_scan(
        db: Session,
        scan_id: str,
        category: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Finding]:
        """List findings for a given scan with optional category and severity filters."""
        query = db.query(Finding).filter(Finding.scan_id == scan_id)
        if category:
            query = query.filter(Finding.category == category)
        if severity:
            query = query.filter(Finding.severity == severity)
        return query.order_by(Finding.creation_timestamp.desc()).all()

    @staticmethod
    def get_finding(db: Session, finding_id: str) -> Optional[Finding]:
        """Retrieve a finding by its ID."""
        return db.query(Finding).filter(Finding.id == finding_id).first()

    @staticmethod
    def update_retest_status(
        db: Session,
        finding_id: str,
        retest_status: str,
    ) -> Optional[Finding]:
        """Update retest status on an existing finding."""
        finding = db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            return None
        finding.retest_status = retest_status
        db.commit()
        db.refresh(finding)
        return finding

    @staticmethod
    def get_severity_distribution(db: Session, scan_id: Optional[str] = None) -> Dict[str, int]:
        """Return counts of findings grouped by severity."""
        query = db.query(Finding.severity, func.count(Finding.id))
        if scan_id:
            query = query.filter(Finding.scan_id == scan_id)
        rows = query.group_by(Finding.severity).all()
        return {row[0]: row[1] for row in rows}

    @staticmethod
    def get_category_distribution(db: Session, scan_id: Optional[str] = None) -> Dict[str, int]:
        """Return counts of findings grouped by threat category."""
        query = db.query(Finding.category, func.count(Finding.id))
        if scan_id:
            query = query.filter(Finding.scan_id == scan_id)
        rows = query.group_by(Finding.category).all()
        return {row[0]: row[1] for row in rows}

    @staticmethod
    def list_all_findings(
        db: Session,
        skip: int = 0,
        limit: int = 50,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        retest_status: Optional[str] = None,
    ) -> List[Finding]:
        """List findings across all scans with optional category, severity, and retest filters."""
        query = db.query(Finding)
        if category:
            query = query.filter(Finding.category == category)
        if severity:
            query = query.filter(Finding.severity == severity)
        if retest_status:
            query = query.filter(Finding.retest_status == retest_status)
        return query.order_by(Finding.creation_timestamp.desc()).offset(skip).limit(limit).all()

    @staticmethod
    def count_all_findings(
        db: Session,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        retest_status: Optional[str] = None,
    ) -> int:
        """Count findings across all scans with optional filters."""
        query = db.query(func.count(Finding.id))
        if category:
            query = query.filter(Finding.category == category)
        if severity:
            query = query.filter(Finding.severity == severity)
        if retest_status:
            query = query.filter(Finding.retest_status == retest_status)
        return query.scalar() or 0


class TestCaseRepository:
    """Repository managing SecurityTestCase persistence, versioning, and lifecycle."""

    @staticmethod
    def get_all(
        db: Session,
        category: Optional[str] = None,
        enabled_only: bool = True,
        dataset_type: Optional[str] = None,
        include_retired: bool = False,
    ) -> List[SecurityTestCase]:
        """Retrieve test cases with optional category, dataset_type, and active status filters."""
        query = db.query(SecurityTestCase)
        if enabled_only and not include_retired:
            query = query.filter(SecurityTestCase.enabled.is_(True))
        if not include_retired:
            query = query.filter(SecurityTestCase.retired.is_(False))
        if category:
            query = query.filter(SecurityTestCase.category == category)
        if dataset_type:
            query = query.filter(SecurityTestCase.dataset_type == dataset_type)
        return query.order_by(SecurityTestCase.id.asc()).all()

    @staticmethod
    def get_by_id(db: Session, case_id: str) -> Optional[SecurityTestCase]:
        """Retrieve a single test case by its unique ID."""
        return db.query(SecurityTestCase).filter(SecurityTestCase.id == case_id).first()

    @staticmethod
    def create_case(db: Session, case_data: dict) -> SecurityTestCase:
        """Create a new versioned test case."""
        now = datetime.now(timezone.utc)
        tc = SecurityTestCase(
            id=case_data["id"],
            version=case_data.get("version", "1.0.0"),
            category=case_data["category"],
            test_input=case_data["input"],
            expected_behavior=case_data["expected_behavior"],
            expected_outcome=case_data.get("expected_outcome", ""),
            test_rationale=case_data.get("rationale", ""),
            objective=case_data.get("objective", case_data.get("rationale", "")),
            tags=case_data.get("tags", []),
            provenance=case_data.get("provenance", "internal_synthetic"),
            license=case_data.get("license", "MIT"),
            enabled=case_data.get("enabled", True),
            retired=case_data.get("retired", False),
            retirement_reason=case_data.get("retirement_reason"),
            dataset_type=case_data.get("dataset_type", "evaluation"),
            suite_version=case_data.get("suite_version", "v1.0.0"),
            metadata_json=case_data.get("metadata", {}),
            created_at=now,
            updated_at=now,
        )
        db.add(tc)
        db.commit()
        db.refresh(tc)
        return tc

    @staticmethod
    def update_case(db: Session, case_id: str, update_data: dict) -> Optional[SecurityTestCase]:
        """Update fields of an existing test case."""
        tc = db.query(SecurityTestCase).filter(SecurityTestCase.id == case_id).first()
        if not tc:
            return None

        if "category" in update_data:
            tc.category = update_data["category"]
        if "input" in update_data:
            tc.test_input = update_data["input"]
        if "expected_behavior" in update_data:
            tc.expected_behavior = update_data["expected_behavior"]
        if "expected_outcome" in update_data:
            tc.expected_outcome = update_data["expected_outcome"]
        if "rationale" in update_data:
            tc.test_rationale = update_data["rationale"]
        if "objective" in update_data:
            tc.objective = update_data["objective"]
        if "tags" in update_data:
            tc.tags = update_data["tags"]
        if "provenance" in update_data:
            tc.provenance = update_data["provenance"]
        if "license" in update_data:
            tc.license = update_data["license"]
        if "enabled" in update_data:
            tc.enabled = update_data["enabled"]
        if "version" in update_data:
            tc.version = update_data["version"]
        if "metadata" in update_data:
            tc.metadata_json = update_data["metadata"]

        tc.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(tc)
        return tc

    @staticmethod
    def retire_case(db: Session, case_id: str, reason: str) -> Optional[SecurityTestCase]:
        """Mark a test case as retired with an audit reason."""
        tc = db.query(SecurityTestCase).filter(SecurityTestCase.id == case_id).first()
        if not tc:
            return None
        tc.retired = True
        tc.enabled = False
        tc.retirement_reason = reason
        tc.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(tc)
        return tc

    @staticmethod
    def bulk_upsert(
        db: Session,
        test_cases: List[dict],
        suite_version: str = "v1.0.0",
        dataset_type: str = "evaluation",
    ) -> int:
        """Insert or update test cases from dataset records with versioning support."""
        count = 0
        now = datetime.now(timezone.utc)
        for tc_data in test_cases:
            existing = (
                db.query(SecurityTestCase)
                .filter(SecurityTestCase.id == tc_data["id"])
                .first()
            )
            if existing:
                existing.version = tc_data.get("version", existing.version or "1.0.0")
                existing.category = tc_data["category"]
                existing.test_input = tc_data["input"]
                existing.expected_behavior = tc_data.get("expected_behavior", "")
                existing.expected_outcome = tc_data.get("expected_outcome", "")
                existing.test_rationale = tc_data.get("rationale", "")
                existing.objective = tc_data.get("objective", tc_data.get("rationale", ""))
                existing.tags = tc_data.get("tags", existing.tags or [])
                existing.provenance = tc_data.get("provenance", existing.provenance or "internal_synthetic")
                existing.license = tc_data.get("license", existing.license or "MIT")
                existing.enabled = tc_data.get("enabled", True)
                existing.retired = tc_data.get("retired", False)
                existing.retirement_reason = tc_data.get("retirement_reason")
                existing.dataset_type = tc_data.get("dataset_type", dataset_type)
                existing.suite_version = suite_version
                existing.metadata_json = tc_data.get("metadata", {})
                existing.updated_at = now
            else:
                tc = SecurityTestCase(
                    id=tc_data["id"],
                    version=tc_data.get("version", "1.0.0"),
                    category=tc_data["category"],
                    test_input=tc_data["input"],
                    expected_behavior=tc_data.get("expected_behavior", ""),
                    expected_outcome=tc_data.get("expected_outcome", ""),
                    test_rationale=tc_data.get("rationale", ""),
                    objective=tc_data.get("objective", tc_data.get("rationale", "")),
                    tags=tc_data.get("tags", []),
                    provenance=tc_data.get("provenance", "internal_synthetic"),
                    license=tc_data.get("license", "MIT"),
                    enabled=tc_data.get("enabled", True),
                    retired=tc_data.get("retired", False),
                    retirement_reason=tc_data.get("retirement_reason"),
                    dataset_type=tc_data.get("dataset_type", dataset_type),
                    suite_version=suite_version,
                    metadata_json=tc_data.get("metadata", {}),
                    created_at=now,
                    updated_at=now,
                )
                db.add(tc)
            count += 1
        db.commit()
        return count


class TestSuiteRepository:
    """Repository managing versioned TestSuiteVersion records."""

    @staticmethod
    def create_suite_version(db: Session, suite_data: dict) -> TestSuiteVersion:
        """Persist a new test suite version metadata record."""
        suite = TestSuiteVersion(
            suite_id=suite_data["suite_id"],
            version=suite_data["version"],
            dataset_type=suite_data.get("dataset_type", "evaluation"),
            description=suite_data.get("description", ""),
            license=suite_data.get("license", "MIT"),
            provenance=suite_data.get("provenance", "internal_synthetic"),
            record_count=suite_data.get("record_count", 0),
            checksum_sha256=suite_data.get("checksum_sha256", ""),
            created_at=datetime.now(timezone.utc),
        )
        db.add(suite)
        db.commit()
        db.refresh(suite)
        return suite

    @staticmethod
    def list_suite_versions(
        db: Session,
        dataset_type: Optional[str] = None,
    ) -> List[TestSuiteVersion]:
        """List all registered test suite versions."""
        query = db.query(TestSuiteVersion)
        if dataset_type:
            query = query.filter(TestSuiteVersion.dataset_type == dataset_type)
        return query.order_by(TestSuiteVersion.created_at.desc()).all()

    @staticmethod
    def get_suite_version(
        db: Session,
        suite_id: str,
        version: str,
    ) -> Optional[TestSuiteVersion]:
        """Retrieve a specific suite version."""
        return (
            db.query(TestSuiteVersion)
            .filter(
                TestSuiteVersion.suite_id == suite_id,
                TestSuiteVersion.version == version,
            )
            .first()
        )


class EvaluationRepository:
    """Repository managing baseline ML ModelEvaluation persistence."""

    @staticmethod
    def record_evaluation(db: Session, evaluation_data: dict) -> ModelEvaluation:
        """Persist a new evaluation record."""
        eval_record = ModelEvaluation(
            dataset_version=evaluation_data["dataset_version"],
            model_version=evaluation_data["model_version"],
            precision=evaluation_data["precision"],
            recall=evaluation_data["recall"],
            f1_score=evaluation_data["f1_score"],
            false_positive_rate=evaluation_data["false_positive_rate"],
            false_negative_rate=evaluation_data["false_negative_rate"],
            confusion_matrix=evaluation_data.get("confusion_matrix", {}),
            per_class_metrics=evaluation_data.get("per_class_metrics", {}),
            configuration=evaluation_data.get("configuration", {}),
        )
        db.add(eval_record)
        db.commit()
        db.refresh(eval_record)
        return eval_record

    @staticmethod
    def get_latest(db: Session) -> Optional[ModelEvaluation]:
        """Fetch the most recent evaluation record."""
        return (
            db.query(ModelEvaluation)
            .order_by(ModelEvaluation.evaluation_timestamp.desc())
            .first()
        )

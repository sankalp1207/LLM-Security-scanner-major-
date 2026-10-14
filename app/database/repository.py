"""Database repositories encapsulating persistence operations for the scanner."""

from datetime import datetime, timezone
from typing import Dict, List, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database.models import Finding, ModelEvaluation, Scan, SecurityTestCase


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
        """Retrieve a scan by its primary key ID."""
        return db.query(Scan).filter(Scan.id == scan_id).first()

    @staticmethod
    def list_scans(db: Session, skip: int = 0, limit: int = 50) -> List[Scan]:
        """List recent scans ordered by start timestamp descending."""
        return (
            db.query(Scan)
            .order_by(Scan.start_timestamp.desc())
            .offset(skip)
            .limit(limit)
            .all()
        )

    @staticmethod
    def update_scan_status(
        db: Session,
        scan_id: str,
        status: str,
        summary: Optional[dict] = None,
    ) -> Optional[Scan]:
        """Update the execution status and summary of a scan."""
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return None

        scan.status = status
        if summary is not None:
            scan.summary = summary
        if status in ("COMPLETED", "FAILED", "PARTIALLY_COMPLETED", "CANCELLED"):
            scan.completion_timestamp = datetime.now(timezone.utc)

        db.commit()
        db.refresh(scan)
        return scan

    @staticmethod
    def get_stats(db: Session) -> Dict[str, int]:
        """Calculate high-level scan counts."""
        total = db.query(func.count(Scan.id)).scalar() or 0
        completed = (
            db.query(func.count(Scan.id)).filter(Scan.status == "COMPLETED").scalar() or 0
        )
        failed = (
            db.query(func.count(Scan.id)).filter(Scan.status == "FAILED").scalar() or 0
        )
        running = (
            db.query(func.count(Scan.id)).filter(Scan.status == "RUNNING").scalar() or 0
        )
        return {
            "total_scans": total,
            "completed_scans": completed,
            "failed_scans": failed,
            "running_scans": running,
        }


class FindingRepository:
    """Repository managing Finding persistence."""

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


class TestCaseRepository:
    """Repository managing SecurityTestCase persistence."""

    @staticmethod
    def get_all(
        db: Session,
        category: Optional[str] = None,
        enabled_only: bool = True,
    ) -> List[SecurityTestCase]:
        """Retrieve test cases with optional filtering."""
        query = db.query(SecurityTestCase)
        if enabled_only:
            query = query.filter(SecurityTestCase.enabled.is_(True))
        if category:
            query = query.filter(SecurityTestCase.category == category)
        return query.all()

    @staticmethod
    def bulk_upsert(db: Session, test_cases: List[dict]) -> int:
        """Insert or update test cases from dataset records."""
        count = 0
        for tc_data in test_cases:
            existing = (
                db.query(SecurityTestCase)
                .filter(SecurityTestCase.id == tc_data["id"])
                .first()
            )
            if existing:
                existing.category = tc_data["category"]
                existing.test_input = tc_data["input"]
                existing.expected_behavior = tc_data.get("expected_behavior", "")
                existing.expected_outcome = tc_data.get("expected_outcome", "")
                existing.test_rationale = tc_data.get("rationale", "")
                existing.enabled = tc_data.get("enabled", True)
                existing.metadata_json = tc_data.get("metadata", {})
            else:
                tc = SecurityTestCase(
                    id=tc_data["id"],
                    category=tc_data["category"],
                    test_input=tc_data["input"],
                    expected_behavior=tc_data.get("expected_behavior", ""),
                    expected_outcome=tc_data.get("expected_outcome", ""),
                    test_rationale=tc_data.get("rationale", ""),
                    enabled=tc_data.get("enabled", True),
                    metadata_json=tc_data.get("metadata", {}),
                )
                db.add(tc)
            count += 1
        db.commit()
        return count


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

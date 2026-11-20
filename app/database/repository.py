"""Database repositories encapsulating persistence operations for the scanner."""

from datetime import datetime, timezone
from typing import Dict, List, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database.models import (
    CopilotConversation,
    CopilotMessage,
    Finding,
    ModelEvaluation,
    Project,
    Remediation,
    RemediationApproval,
    RemediationExecution,
    RemediationPatch,
    Scan,
    ScanEvent,
    SecurityTestCase,
    TargetConfiguration,
    TestExecution,
    TestSuiteVersion,
    UserOnboarding,
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
        project_id: Optional[str] = None,
        user_id: str = "default_user",
        preset: str = "quick_scan",
        target_configuration_id: Optional[str] = None,
        configuration_snapshot: Optional[dict] = None,
        status: str = "PENDING",
        total_tests: int = 0,
    ) -> Scan:
        """Create and persist a new Scan record."""
        scan = Scan(
            id=scan_id or None,
            project_id=project_id,
            user_id=user_id,
            preset=preset,
            target_identifier=target_identifier,
            target_configuration_id=target_configuration_id,
            status=status,
            configuration=configuration,
            configuration_snapshot=configuration_snapshot or configuration,
            start_timestamp=datetime.now(timezone.utc),
            summary={},
            scanner_version=scanner_version,
            total_tests=total_tests,
            completed_tests=0,
            passed_tests=0,
            failed_tests=0,
            inconclusive_tests=0,
            skipped_tests=0,
            execution_errors=0,
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
    def list_scans(
        db: Session, skip: int = 0, limit: int = 20, user_id: Optional[str] = None
    ) -> List[Scan]:
        """Retrieve paginated list of scans ordered by start time descending."""
        query = db.query(Scan)
        if user_id is not None:
            query = query.filter(Scan.user_id == user_id)
        return query.order_by(Scan.start_timestamp.desc()).offset(skip).limit(limit).all()

    @staticmethod
    def list_scans_by_project(
        db: Session,
        project_id: str,
        skip: int = 0,
        limit: int = 50,
        status: Optional[str] = None,
    ) -> List[Scan]:
        """Retrieve paginated scans for a project."""
        q = db.query(Scan).filter(Scan.project_id == project_id)
        if status:
            q = q.filter(Scan.status == status.upper())
        return q.order_by(Scan.start_timestamp.desc()).offset(skip).limit(limit).all()

    @staticmethod
    def count_scans(db: Session) -> int:
        """Return total count of scan records."""
        return db.query(func.count(Scan.id)).scalar() or 0

    @staticmethod
    def count_scans_by_project(db: Session, project_id: str, status: Optional[str] = None) -> int:
        """Count scans for a project."""
        q = db.query(func.count(Scan.id)).filter(Scan.project_id == project_id)
        if status:
            q = q.filter(Scan.status == status.upper())
        return q.scalar() or 0

    @staticmethod
    def update_scan_status(
        db: Session,
        scan_id: str,
        status: str,
        summary: Optional[dict] = None,
        completed_at: Optional[datetime] = None,
        total_tests: Optional[int] = None,
        completed_tests: Optional[int] = None,
        passed_tests: Optional[int] = None,
        failed_tests: Optional[int] = None,
        inconclusive_tests: Optional[int] = None,
        skipped_tests: Optional[int] = None,
        execution_errors: Optional[int] = None,
        cancellation_reason: Optional[str] = None,
        failure_reason: Optional[str] = None,
    ) -> Optional[Scan]:
        """Update status, lifecycle timestamps, and test execution metrics of a scan."""
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return None
        scan.status = status
        if summary is not None:
            scan.summary = summary
        if total_tests is not None:
            scan.total_tests = total_tests
        if completed_tests is not None:
            scan.completed_tests = completed_tests
        if passed_tests is not None:
            scan.passed_tests = passed_tests
        if failed_tests is not None:
            scan.failed_tests = failed_tests
        if inconclusive_tests is not None:
            scan.inconclusive_tests = inconclusive_tests
        if skipped_tests is not None:
            scan.skipped_tests = skipped_tests
        if execution_errors is not None:
            scan.execution_errors = execution_errors
        if cancellation_reason is not None:
            scan.cancellation_reason = cancellation_reason
        if failure_reason is not None:
            scan.failure_reason = failure_reason
        if status in ("COMPLETED", "FAILED", "CANCELLED", "PARTIALLY_COMPLETED"):
            scan.completion_timestamp = completed_at or datetime.now(timezone.utc)
        db.commit()
        db.refresh(scan)
        return scan

    @staticmethod
    def cancel_scan(db: Session, scan_id: str, reason: str = "Cancelled by user") -> Optional[Scan]:
        """Request cancellation of an active scan."""
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return None
        if scan.status in ("COMPLETED", "FAILED", "CANCELLED"):
            return scan  # Already in terminal state
        scan.status = "CANCELLED"
        scan.cancellation_reason = reason
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


class TestExecutionRepository:
    """Repository managing TestExecution telemetry persistence."""

    @staticmethod
    def create_execution(
        db: Session,
        scan_id: str,
        test_case_id: str,
        category: str,
        input_fixture: str,
        expected_behavior: str,
        observed_behavior: str,
        execution_status: str,
        latency_ms: float = 0.0,
        response_status: Optional[int] = None,
        detection_result: Optional[dict] = None,
        evidence: Optional[dict] = None,
        test_version: str = "1.0.0",
        error_message: Optional[str] = None,
        started_at: Optional[datetime] = None,
        completed_at: Optional[datetime] = None,
    ) -> TestExecution:
        """Create and persist a test execution record."""
        record = TestExecution(
            scan_id=scan_id,
            test_case_id=test_case_id,
            category=category,
            test_version=test_version,
            input_fixture=input_fixture,
            expected_behavior=expected_behavior,
            observed_behavior=observed_behavior,
            execution_status=execution_status,
            latency_ms=round(latency_ms, 2),
            response_status=response_status,
            detection_result=detection_result or {},
            evidence=evidence or {},
            error_message=error_message,
            started_at=started_at or datetime.now(timezone.utc),
            completed_at=completed_at or datetime.now(timezone.utc),
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record

    @staticmethod
    def list_executions_by_scan(
        db: Session,
        scan_id: str,
        status: Optional[str] = None,
        category: Optional[str] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> List[TestExecution]:
        """Fetch paginated test execution records for a scan."""
        q = db.query(TestExecution).filter(TestExecution.scan_id == scan_id)
        if status:
            q = q.filter(TestExecution.execution_status == status.upper())
        if category:
            q = q.filter(TestExecution.category == category.lower())
        return q.order_by(TestExecution.started_at.asc()).offset(skip).limit(limit).all()

    @staticmethod
    def count_executions_by_scan(
        db: Session,
        scan_id: str,
        status: Optional[str] = None,
        category: Optional[str] = None,
    ) -> int:
        """Count test executions for a scan."""
        q = db.query(func.count(TestExecution.id)).filter(TestExecution.scan_id == scan_id)
        if status:
            q = q.filter(TestExecution.execution_status == status.upper())
        if category:
            q = q.filter(TestExecution.category == category.lower())
        return q.scalar() or 0


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
        user_id: Optional[str] = None,
    ) -> List[Finding]:
        """List findings across all scans with optional category, severity, and retest filters."""
        query = db.query(Finding)
        if user_id is not None:
            query = query.join(Scan, Finding.scan_id == Scan.id).filter(Scan.user_id == user_id)
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


class ProjectRepository:
    """Repository managing Project lifecycle, configuration, and ownership isolation."""

    @staticmethod
    def create_project(
        db: Session,
        name: str,
        owner_id: str = "default_user",
        description: str = "",
        application_type: str = "rag",
        environment: str = "development",
        target_type: str = "demo",
        default_scan_preferences: Optional[dict] = None,
        onboarding_completed: bool = False,
    ) -> Project:
        """Create and persist a new Project record."""
        project = Project(
            owner_id=owner_id,
            name=name,
            description=description,
            application_type=application_type,
            environment=environment,
            target_type=target_type,
            default_scan_preferences=default_scan_preferences or {
                "direct_prompt_injection": True,
                "indirect_prompt_injection": True,
                "jailbreak_testing": True,
                "sensitive_data_leakage": True,
                "rag_security": True,
                "agent_security": False,
                "input_validation": True,
                "output_validation": True,
                "scan_preference": "full",
                "adversarial_mutation_fuzzing": True,
            },
            onboarding_completed=onboarding_completed,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(project)
        db.commit()
        db.refresh(project)
        return project

    @staticmethod
    def get_project(
        db: Session,
        project_id: str,
        owner_id: Optional[str] = None,
    ) -> Optional[Project]:
        """Retrieve project by ID, optionally scoped to owner."""
        query = db.query(Project).filter(Project.id == project_id)
        if owner_id:
            query = query.filter(Project.owner_id == owner_id)
        return query.first()

    @staticmethod
    def get_project_by_name(
        db: Session,
        name: str,
        owner_id: str = "default_user",
    ) -> Optional[Project]:
        """Check duplicate project name within the same owner scope."""
        return (
            db.query(Project)
            .filter(Project.owner_id == owner_id, Project.name == name)
            .first()
        )

    @staticmethod
    def list_projects(
        db: Session,
        owner_id: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
        include_archived: bool = False,
    ) -> List[Project]:
        """List projects with pagination, ordering, and optional owner filtering."""
        query = db.query(Project)
        if owner_id:
            query = query.filter(Project.owner_id == owner_id)
        if not include_archived:
            query = query.filter(Project.is_archived.is_(False))
        return (
            query.order_by(Project.created_at.desc())
            .offset(skip)
            .limit(limit)
            .all()
        )

    @staticmethod
    def count_projects(
        db: Session,
        owner_id: Optional[str] = None,
        include_archived: bool = False,
    ) -> int:
        """Count total projects under the specified criteria."""
        query = db.query(func.count(Project.id))
        if owner_id:
            query = query.filter(Project.owner_id == owner_id)
        if not include_archived:
            query = query.filter(Project.is_archived.is_(False))
        return query.scalar() or 0

    @staticmethod
    def update_project(
        db: Session,
        project_id: str,
        updates: dict,
        owner_id: Optional[str] = None,
    ) -> Optional[Project]:
        """Update fields on an existing project."""
        project = ProjectRepository.get_project(db, project_id, owner_id=owner_id)
        if not project:
            return None
        for key, val in updates.items():
            if val is not None and hasattr(project, key):
                setattr(project, key, val)
        project.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(project)
        return project

    @staticmethod
    def delete_project(
        db: Session,
        project_id: str,
        owner_id: Optional[str] = None,
    ) -> bool:
        """Safely delete project and associated target configuration."""
        project = ProjectRepository.get_project(db, project_id, owner_id=owner_id)
        if not project:
            return False
        db.delete(project)
        db.commit()
        return True


class TargetConfigurationRepository:
    """Repository managing target endpoint parameters and encrypted credentials."""

    @staticmethod
    def upsert_configuration(
        db: Session,
        project_id: str,
        provider: str = "demo",
        endpoint_url: str = "http://127.0.0.1:8000/api/v1/demo-rag/query",
        model_identifier: str = "",
        auth_type: str = "none",
        encrypted_credential: str = "",
        connection_timeout: float = 10.0,
    ) -> TargetConfiguration:
        """Create or update target connection configuration for a project."""
        config = (
            db.query(TargetConfiguration)
            .filter(TargetConfiguration.project_id == project_id)
            .first()
        )
        now = datetime.now(timezone.utc)
        if config:
            config.provider = provider
            config.endpoint_url = endpoint_url
            config.model_identifier = model_identifier
            config.auth_type = auth_type
            if encrypted_credential:
                config.encrypted_credential = encrypted_credential
            config.connection_timeout = connection_timeout
            config.updated_at = now
        else:
            config = TargetConfiguration(
                project_id=project_id,
                provider=provider,
                endpoint_url=endpoint_url,
                model_identifier=model_identifier,
                auth_type=auth_type,
                encrypted_credential=encrypted_credential,
                connection_timeout=connection_timeout,
                connection_status="UNVERIFIED",
                created_at=now,
                updated_at=now,
            )
            db.add(config)
        db.commit()
        db.refresh(config)
        return config

    @staticmethod
    def get_configuration(db: Session, project_id: str) -> Optional[TargetConfiguration]:
        """Fetch target configuration for a given project."""
        return (
            db.query(TargetConfiguration)
            .filter(TargetConfiguration.project_id == project_id)
            .first()
        )

    @staticmethod
    def update_verification_status(
        db: Session,
        project_id: str,
        status: str,
        details: Optional[dict] = None,
    ) -> Optional[TargetConfiguration]:
        """Update live connection verification result."""
        config = TargetConfigurationRepository.get_configuration(db, project_id)
        if not config:
            return None
        config.connection_status = status
        config.last_verified_at = datetime.now(timezone.utc)
        if details is not None:
            config.verification_details = details
        config.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(config)
        return config


class UserOnboardingRepository:
    """Repository persisting first-time onboarding and demo exploration state per user."""

    @staticmethod
    def get_status(db: Session, user_id: str = "default_user") -> Optional[UserOnboarding]:
        """Retrieve onboarding record for user."""
        return (
            db.query(UserOnboarding)
            .filter(UserOnboarding.user_id == user_id)
            .first()
        )

    @staticmethod
    def complete_onboarding(
        db: Session,
        user_id: str = "default_user",
        selected_demo: bool = False,
        active_project_id: Optional[str] = None,
    ) -> UserOnboarding:
        """Mark onboarding as completed for user."""
        record = UserOnboardingRepository.get_status(db, user_id)
        now = datetime.now(timezone.utc)
        if record:
            record.is_completed = True
            record.selected_demo = selected_demo
            if active_project_id:
                record.active_project_id = active_project_id
            record.completed_at = now
            record.updated_at = now
        else:
            record = UserOnboarding(
                user_id=user_id,
                is_completed=True,
                selected_demo=selected_demo,
                active_project_id=active_project_id,
                completed_at=now,
                created_at=now,
                updated_at=now,
            )
            db.add(record)
        db.commit()
        db.refresh(record)
        return record

    @staticmethod
    def reset_onboarding(db: Session, user_id: str = "default_user") -> UserOnboarding:
        """Reset onboarding state to allow revisiting the setup wizard from settings."""
        record = UserOnboardingRepository.get_status(db, user_id)
        now = datetime.now(timezone.utc)
        if record:
            record.is_completed = False
            record.completed_at = None
            record.updated_at = now
        else:
            record = UserOnboarding(
                user_id=user_id,
                is_completed=False,
                selected_demo=False,
                created_at=now,
                updated_at=now,
            )
            db.add(record)
        db.commit()
        db.refresh(record)
        return record


class ScanEventRepository:
    """Repository managing structured scan lifecycle and execution event persistence."""

    @staticmethod
    def create_event(
        db: Session,
        scan_id: str,
        event_type: str,
        sequence: int,
        payload: dict,
        version: str = "1.0",
        event_id: Optional[str] = None,
    ) -> ScanEvent:
        """Create and persist a scan event record."""
        event = ScanEvent(
            id=event_id,
            scan_id=scan_id,
            event_type=event_type,
            sequence=sequence,
            payload=payload or {},
            version=version,
            created_at=datetime.now(timezone.utc),
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event

    @staticmethod
    def list_events_by_scan(
        db: Session,
        scan_id: str,
        since_seq: int = 0,
        limit: int = 100,
        event_type: Optional[str] = None,
    ) -> List[ScanEvent]:
        """Fetch chronological scan events with cursor pagination based on sequence number."""
        q = db.query(ScanEvent).filter(
            ScanEvent.scan_id == scan_id,
            ScanEvent.sequence > since_seq,
        )
        if event_type:
            q = q.filter(ScanEvent.event_type == event_type.upper())
        return q.order_by(ScanEvent.sequence.asc()).limit(limit).all()

    @staticmethod
    def get_latest_sequence(db: Session, scan_id: str) -> int:
        """Retrieve the maximum sequence number recorded for a scan, or 0 if none exist."""
        max_seq = db.query(func.max(ScanEvent.sequence)).filter(ScanEvent.scan_id == scan_id).scalar()
        return max_seq or 0

    @staticmethod
    def count_events(db: Session, scan_id: str) -> int:
        """Count total events for a scan."""
        return db.query(func.count(ScanEvent.id)).filter(ScanEvent.scan_id == scan_id).scalar() or 0


class CopilotRepository:
    """Repository managing persistent AI Security Copilot conversation and message storage."""

    @staticmethod
    def create_conversation(
        db: Session,
        user_id: str = "default_user",
        project_id: Optional[str] = None,
        title: str = "New Security Conversation",
    ) -> CopilotConversation:
        """Create and persist a new Copilot chat conversation session."""
        now = datetime.now(timezone.utc)
        conversation = CopilotConversation(
            user_id=user_id,
            project_id=project_id,
            title=title.strip() if title else "New Security Conversation",
            created_at=now,
            updated_at=now,
        )
        db.add(conversation)
        db.commit()
        db.refresh(conversation)
        return conversation

    @staticmethod
    def get_conversation(
        db: Session,
        conversation_id: str,
        user_id: Optional[str] = None,
    ) -> Optional[CopilotConversation]:
        """Fetch a conversation by ID, enforcing user identity boundary when provided."""
        q = db.query(CopilotConversation).filter(CopilotConversation.id == conversation_id)
        if user_id:
            q = q.filter(CopilotConversation.user_id == user_id)
        return q.first()

    @staticmethod
    def list_conversations(
        db: Session,
        user_id: str = "default_user",
        project_id: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> List[CopilotConversation]:
        """List conversations belonging to a user, optionally filtered by project workspace."""
        q = db.query(CopilotConversation).filter(CopilotConversation.user_id == user_id)
        if project_id:
            q = q.filter(CopilotConversation.project_id == project_id)
        return q.order_by(CopilotConversation.updated_at.desc()).offset(skip).limit(limit).all()

    @staticmethod
    def count_conversations(
        db: Session,
        user_id: str = "default_user",
        project_id: Optional[str] = None,
    ) -> int:
        """Count total conversations for a user."""
        q = db.query(func.count(CopilotConversation.id)).filter(CopilotConversation.user_id == user_id)
        if project_id:
            q = q.filter(CopilotConversation.project_id == project_id)
        return q.scalar() or 0

    @staticmethod
    def update_conversation_title(
        db: Session,
        conversation_id: str,
        title: str,
        user_id: Optional[str] = None,
    ) -> Optional[CopilotConversation]:
        """Update conversation title."""
        conv = CopilotRepository.get_conversation(db, conversation_id=conversation_id, user_id=user_id)
        if not conv:
            return None
        conv.title = title.strip()
        conv.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(conv)
        return conv

    @staticmethod
    def delete_conversation(
        db: Session,
        conversation_id: str,
        user_id: Optional[str] = None,
    ) -> bool:
        """Delete a conversation and all cascaded messages."""
        conv = CopilotRepository.get_conversation(db, conversation_id=conversation_id, user_id=user_id)
        if not conv:
            return False
        db.delete(conv)
        db.commit()
        return True

    @staticmethod
    def add_message(
        db: Session,
        conversation_id: str,
        role: str,
        content: str,
        referenced_evidence_ids: Optional[dict] = None,
    ) -> CopilotMessage:
        """Append an individual user or assistant message to a conversation."""
        now = datetime.now(timezone.utc)
        message = CopilotMessage(
            conversation_id=conversation_id,
            role=role,
            content=content,
            referenced_evidence_ids=referenced_evidence_ids or {},
            created_at=now,
        )
        db.add(message)

        # Update parent conversation updated_at
        conv = db.query(CopilotConversation).filter(CopilotConversation.id == conversation_id).first()
        if conv:
            conv.updated_at = now

        db.commit()
        db.refresh(message)
        return message

    @staticmethod
    def list_messages(
        db: Session,
        conversation_id: str,
        skip: int = 0,
        limit: int = 100,
    ) -> List[CopilotMessage]:
        """Retrieve chronological messages for a conversation session."""
        return (
            db.query(CopilotMessage)
            .filter(CopilotMessage.conversation_id == conversation_id)
            .order_by(CopilotMessage.created_at.asc())
            .offset(skip)
            .limit(limit)
            .all()
        )

    @staticmethod
    def count_messages(db: Session, conversation_id: str) -> int:
        """Count total messages in a conversation."""
        return (
            db.query(func.count(CopilotMessage.id))
            .filter(CopilotMessage.conversation_id == conversation_id)
            .scalar()
            or 0
        )


class RemediationRepository:
    """Repository managing Remediation, Patch, Approval, and Execution persistence."""

    @staticmethod
    def create_remediation(
        db: Session,
        finding_id: str,
        user_id: str,
        project_id: Optional[str] = None,
        summary: str = "Vulnerability Remediation",
        root_cause_analysis: str = "",
        affected_component: str = "unknown",
        status: str = "ANALYZING",
    ) -> Remediation:
        """Create and persist an initial remediation entity."""
        now = datetime.now(timezone.utc)
        record = Remediation(
            project_id=project_id,
            finding_id=finding_id,
            user_id=user_id,
            status=status,
            summary=summary,
            root_cause_analysis=root_cause_analysis,
            affected_component=affected_component,
            created_at=now,
            updated_at=now,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record

    @staticmethod
    def get_remediation(db: Session, remediation_id: str) -> Optional[Remediation]:
        """Fetch remediation record by ID."""
        return db.query(Remediation).filter(Remediation.id == remediation_id).first()

    @staticmethod
    def update_remediation_status(db: Session, remediation_id: str, status: str) -> Optional[Remediation]:
        """Update remediation lifecycle state."""
        rec = db.query(Remediation).filter(Remediation.id == remediation_id).first()
        if not rec:
            return None
        rec.status = status
        rec.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(rec)
        return rec

    @staticmethod
    def update_remediation(
        db: Session,
        remediation_id: str,
        summary: Optional[str] = None,
        root_cause_analysis: Optional[str] = None,
        affected_component: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Optional[Remediation]:
        """Update remediation details."""
        rec = db.query(Remediation).filter(Remediation.id == remediation_id).first()
        if not rec:
            return None
        if summary is not None:
            rec.summary = summary
        if root_cause_analysis is not None:
            rec.root_cause_analysis = root_cause_analysis
        if affected_component is not None:
            rec.affected_component = affected_component
        if status is not None:
            rec.status = status
        rec.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(rec)
        return rec

    @staticmethod
    def list_remediations(
        db: Session,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
        finding_id: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> List[Remediation]:
        """List remediations matching query filters."""
        q = db.query(Remediation)
        if project_id:
            q = q.filter(Remediation.project_id == project_id)
        if user_id:
            q = q.filter(Remediation.user_id == user_id)
        if finding_id:
            q = q.filter(Remediation.finding_id == finding_id)
        return q.order_by(Remediation.created_at.desc()).offset(skip).limit(limit).all()

    @staticmethod
    def count_remediations(
        db: Session,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
        finding_id: Optional[str] = None,
    ) -> int:
        """Count total remediations matching query filters."""
        q = db.query(func.count(Remediation.id))
        if project_id:
            q = q.filter(Remediation.project_id == project_id)
        if user_id:
            q = q.filter(Remediation.user_id == user_id)
        if finding_id:
            q = q.filter(Remediation.finding_id == finding_id)
        return q.scalar() or 0

    @staticmethod
    def create_patch(
        db: Session,
        remediation_id: str,
        summary: str,
        files_manifest: list,
        diff_content: str,
        source_hashes: dict,
        validation_status: str = "PENDING",
        validation_errors: Optional[list] = None,
        risks: Optional[list] = None,
        verification_steps: Optional[list] = None,
        patch_version: Optional[int] = None,
    ) -> RemediationPatch:
        """Create and persist a proposed patch version for a remediation."""
        if patch_version is None:
            existing_count = (
                db.query(func.count(RemediationPatch.id))
                .filter(RemediationPatch.remediation_id == remediation_id)
                .scalar()
                or 0
            )
            patch_version = existing_count + 1

        patch = RemediationPatch(
            remediation_id=remediation_id,
            patch_version=patch_version,
            summary=summary,
            files_manifest=files_manifest,
            diff_content=diff_content,
            source_hashes=source_hashes,
            validation_status=validation_status,
            validation_errors=validation_errors or [],
            risks=risks or [],
            verification_steps=verification_steps or [],
            created_at=datetime.now(timezone.utc),
        )
        db.add(patch)
        db.commit()
        db.refresh(patch)
        return patch

    @staticmethod
    def get_patch(db: Session, patch_id: str) -> Optional[RemediationPatch]:
        """Fetch patch by ID."""
        return db.query(RemediationPatch).filter(RemediationPatch.id == patch_id).first()

    @staticmethod
    def get_latest_patch(db: Session, remediation_id: str) -> Optional[RemediationPatch]:
        """Fetch latest patch version for a remediation."""
        return (
            db.query(RemediationPatch)
            .filter(RemediationPatch.remediation_id == remediation_id)
            .order_by(RemediationPatch.patch_version.desc())
            .first()
        )

    @staticmethod
    def list_patches(db: Session, remediation_id: str) -> List[RemediationPatch]:
        """List all patches for a remediation."""
        return (
            db.query(RemediationPatch)
            .filter(RemediationPatch.remediation_id == remediation_id)
            .order_by(RemediationPatch.patch_version.asc())
            .all()
        )

    @staticmethod
    def update_patch_validation(
        db: Session,
        patch_id: str,
        validation_status: str,
        validation_errors: list,
    ) -> Optional[RemediationPatch]:
        """Update validation outcome for a patch."""
        patch = db.query(RemediationPatch).filter(RemediationPatch.id == patch_id).first()
        if not patch:
            return None
        patch.validation_status = validation_status
        patch.validation_errors = validation_errors
        db.commit()
        db.refresh(patch)
        return patch

    @staticmethod
    def create_approval(
        db: Session,
        patch_id: str,
        user_id: str,
        decision: str,
        reason: str = "",
    ) -> RemediationApproval:
        """Record explicit human approval or rejection of a patch."""
        approval = RemediationApproval(
            patch_id=patch_id,
            user_id=user_id,
            decision=decision,
            reason=reason,
            created_at=datetime.now(timezone.utc),
        )
        db.add(approval)
        db.commit()
        db.refresh(approval)
        return approval

    @staticmethod
    def get_latest_approval(db: Session, patch_id: str) -> Optional[RemediationApproval]:
        """Fetch the latest approval or rejection record for a patch."""
        return (
            db.query(RemediationApproval)
            .filter(RemediationApproval.patch_id == patch_id)
            .order_by(RemediationApproval.created_at.desc())
            .first()
        )

    @staticmethod
    def create_execution(
        db: Session,
        remediation_id: str,
        patch_id: str,
        execution_status: str = "APPLIED",
        backup_manifest: Optional[dict] = None,
        test_summary: Optional[dict] = None,
        retest_status: str = "INCONCLUSIVE",
        retest_evidence: Optional[dict] = None,
        error_message: Optional[str] = None,
    ) -> RemediationExecution:
        """Create and persist an execution record tracking patch application and retest."""
        now = datetime.now(timezone.utc)
        record = RemediationExecution(
            remediation_id=remediation_id,
            patch_id=patch_id,
            execution_status=execution_status,
            backup_manifest=backup_manifest or {},
            test_summary=test_summary or {},
            retest_status=retest_status,
            retest_evidence=retest_evidence or {},
            error_message=error_message,
            started_at=now,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record

    @staticmethod
    def update_execution(
        db: Session,
        execution_id: str,
        execution_status: Optional[str] = None,
        test_summary: Optional[dict] = None,
        retest_status: Optional[str] = None,
        retest_evidence: Optional[dict] = None,
        error_message: Optional[str] = None,
        completed_at: Optional[datetime] = None,
    ) -> Optional[RemediationExecution]:
        """Update an execution record with test and retest outcomes."""
        rec = db.query(RemediationExecution).filter(RemediationExecution.id == execution_id).first()
        if not rec:
            return None
        if execution_status is not None:
            rec.execution_status = execution_status
        if test_summary is not None:
            rec.test_summary = test_summary
        if retest_status is not None:
            rec.retest_status = retest_status
        if retest_evidence is not None:
            rec.retest_evidence = retest_evidence
        if error_message is not None:
            rec.error_message = error_message
        if completed_at is not None:
            rec.completed_at = completed_at
        db.commit()
        db.refresh(rec)
        return rec

    @staticmethod
    def get_latest_execution(db: Session, remediation_id: str) -> Optional[RemediationExecution]:
        """Fetch the most recent execution for a remediation."""
        return (
            db.query(RemediationExecution)
            .filter(RemediationExecution.remediation_id == remediation_id)
            .order_by(RemediationExecution.started_at.desc())
            .first()
        )





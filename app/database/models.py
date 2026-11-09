"""SQLAlchemy ORM models for scans, findings, test cases, suites, and model evaluations."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from app.database.connection import Base


def generate_uuid() -> str:
    """Generate a random UUID string."""
    return str(uuid.uuid4())


class Scan(Base):
    """Database model for security scan executions."""

    __tablename__ = "scans"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    project_id = Column(String(64), ForeignKey("projects.id", ondelete="SET NULL"), nullable=True, index=True)
    user_id = Column(String(64), default="default_user", nullable=False, index=True)
    target_identifier = Column(String(255), nullable=False, index=True)
    target_configuration_id = Column(String(64), ForeignKey("target_configurations.id", ondelete="SET NULL"), nullable=True)
    preset = Column(String(32), default="quick_scan", nullable=False, index=True)
    status = Column(String(32), default="CREATED", nullable=False, index=True)
    configuration = Column(JSON, default=dict, nullable=False)
    configuration_snapshot = Column(JSON, default=dict, nullable=False)
    start_timestamp = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    completion_timestamp = Column(DateTime(timezone=True), nullable=True)
    summary = Column(JSON, default=dict, nullable=False)
    scanner_version = Column(String(32), default="1.0.0", nullable=False)

    # Test count metrics
    total_tests = Column(Integer, default=0, nullable=False)
    completed_tests = Column(Integer, default=0, nullable=False)
    passed_tests = Column(Integer, default=0, nullable=False)
    failed_tests = Column(Integer, default=0, nullable=False)
    inconclusive_tests = Column(Integer, default=0, nullable=False)
    skipped_tests = Column(Integer, default=0, nullable=False)
    execution_errors = Column(Integer, default=0, nullable=False)

    # Lifecycle diagnostics
    cancellation_reason = Column(Text, nullable=True)
    failure_reason = Column(Text, nullable=True)

    # Relationships
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    test_executions = relationship("TestExecution", back_populates="scan", cascade="all, delete-orphan")
    events = relationship("ScanEvent", back_populates="scan", cascade="all, delete-orphan")
    project = relationship("Project", back_populates="scans")


class Finding(Base):
    """Database model for identified security vulnerabilities and observations."""

    __tablename__ = "findings"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    scan_id = Column(String(64), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    category = Column(String(64), nullable=False, index=True)
    severity = Column(String(32), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    evidence = Column(JSON, default=dict, nullable=False)
    confidence_score = Column(Float, nullable=True)
    target_component = Column(String(64), default="unknown", nullable=False)
    affected_test_case = Column(String(64), default="", nullable=False)
    detection_method = Column(String(64), default="", nullable=False)
    remediation = Column(Text, default="", nullable=False)
    creation_timestamp = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    retest_status = Column(String(32), default="NOT_RETESTED", nullable=False)

    # Relationships
    scan = relationship("Scan", back_populates="findings")


class TestExecution(Base):
    """Database model for individual security test executions and observed telemetry."""

    __tablename__ = "test_executions"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    scan_id = Column(String(64), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    test_case_id = Column(String(64), nullable=False, index=True)
    category = Column(String(64), nullable=False, index=True)
    test_version = Column(String(32), default="1.0.0", nullable=False)
    input_fixture = Column(Text, nullable=False)
    expected_behavior = Column(String(128), default="blocked_or_safe", nullable=False)
    observed_behavior = Column(Text, default="", nullable=False)
    execution_status = Column(String(32), default="PASSED", nullable=False, index=True)  # PASSED, FAILED, INCONCLUSIVE, SKIPPED, ERROR
    latency_ms = Column(Float, default=0.0, nullable=False)
    response_status = Column(Integer, nullable=True)
    detection_result = Column(JSON, default=dict, nullable=False)
    evidence = Column(JSON, default=dict, nullable=False)
    error_message = Column(Text, nullable=True)
    started_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    scan = relationship("Scan", back_populates="test_executions")


class ScanEvent(Base):
    """Database model for structured scan lifecycle and execution progress events."""

    __tablename__ = "scan_events"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    scan_id = Column(String(64), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type = Column(String(64), nullable=False, index=True)
    sequence = Column(Integer, nullable=False, index=True)
    payload = Column(JSON, default=dict, nullable=False)
    version = Column(String(16), default="1.0", nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # Relationships
    scan = relationship("Scan", back_populates="events")


class TestSuiteVersion(Base):
    """Database model for versioned test suites and dataset packages."""

    __tablename__ = "test_suite_versions"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    suite_id = Column(String(64), nullable=False, index=True)
    version = Column(String(32), nullable=False, index=True)
    dataset_type = Column(String(32), default="evaluation", nullable=False, index=True)
    description = Column(Text, default="", nullable=False)
    license = Column(String(64), default="MIT", nullable=False)
    provenance = Column(String(128), default="internal_synthetic", nullable=False)
    record_count = Column(Integer, default=0, nullable=False)
    checksum_sha256 = Column(String(64), default="", nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class SecurityTestCase(Base):
    """Database model for structured versioned security test cases."""

    __tablename__ = "security_test_cases"

    id = Column(String(64), primary_key=True)
    version = Column(String(32), default="1.0.0", nullable=False)
    category = Column(String(64), nullable=False, index=True)
    test_input = Column(Text, nullable=False)
    expected_behavior = Column(String(128), nullable=False)
    expected_outcome = Column(String(128), default="", nullable=False)
    test_rationale = Column(Text, default="", nullable=False)
    objective = Column(Text, default="", nullable=False)
    tags = Column(JSON, default=list, nullable=False)
    provenance = Column(String(128), default="internal_synthetic", nullable=False)
    license = Column(String(64), default="MIT", nullable=False)
    enabled = Column(Boolean, default=True, nullable=False, index=True)
    retired = Column(Boolean, default=False, nullable=False, index=True)
    retirement_reason = Column(Text, nullable=True)
    dataset_type = Column(String(32), default="evaluation", nullable=False, index=True)
    suite_version = Column(String(32), default="v1.0.0", nullable=False)
    metadata_json = Column(JSON, default=dict, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class ModelEvaluation(Base):
    """Database model for recording baseline ML classifier evaluation metrics."""

    __tablename__ = "model_evaluations"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    dataset_version = Column(String(64), nullable=False)
    model_version = Column(String(64), nullable=False)
    evaluation_timestamp = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    precision = Column(Float, nullable=False)
    recall = Column(Float, nullable=False)
    f1_score = Column(Float, nullable=False)
    false_positive_rate = Column(Float, nullable=False)
    false_negative_rate = Column(Float, nullable=False)
    confusion_matrix = Column(JSON, default=dict, nullable=False)
    per_class_metrics = Column(JSON, default=dict, nullable=False)
    configuration = Column(JSON, default=dict, nullable=False)


class Project(Base):
    """Database model for enterprise security assessment projects."""

    __tablename__ = "projects"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    owner_id = Column(String(64), default="default_user", nullable=False, index=True)
    name = Column(String(128), nullable=False, index=True)
    description = Column(Text, default="", nullable=False)
    application_type = Column(String(64), default="rag", nullable=False)
    environment = Column(String(32), default="development", nullable=False)
    target_type = Column(String(32), default="demo", nullable=False)
    default_scan_preferences = Column(JSON, default=dict, nullable=False)
    is_archived = Column(Boolean, default=False, nullable=False, index=True)
    onboarding_completed = Column(Boolean, default=False, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    target_configuration = relationship(
        "TargetConfiguration",
        back_populates="project",
        uselist=False,
        cascade="all, delete-orphan",
    )
    scans = relationship("Scan", back_populates="project")


class TargetConfiguration(Base):
    """Database model for project destination and LLM target connection parameters."""

    __tablename__ = "target_configurations"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    project_id = Column(String(64), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    provider = Column(String(64), default="demo", nullable=False)
    endpoint_url = Column(String(512), nullable=False)
    model_identifier = Column(String(128), default="", nullable=False)
    auth_type = Column(String(32), default="none", nullable=False)
    encrypted_credential = Column(Text, default="", nullable=False)
    connection_timeout = Column(Float, default=10.0, nullable=False)
    connection_status = Column(String(32), default="UNVERIFIED", nullable=False)
    last_verified_at = Column(DateTime(timezone=True), nullable=True)
    verification_details = Column(JSON, default=dict, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    project = relationship("Project", back_populates="target_configuration")


class UserOnboarding(Base):
    """Database model for persisting onboarding completion per user."""

    __tablename__ = "user_onboardings"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    user_id = Column(String(64), unique=True, nullable=False, index=True)
    is_completed = Column(Boolean, default=False, nullable=False)
    selected_demo = Column(Boolean, default=False, nullable=False)
    active_project_id = Column(String(64), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

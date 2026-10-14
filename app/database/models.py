"""SQLAlchemy ORM models for scans, findings, test cases, and model evaluations."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
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
    target_identifier = Column(String(255), nullable=False, index=True)
    status = Column(String(32), default="PENDING", nullable=False, index=True)
    configuration = Column(JSON, default=dict, nullable=False)
    start_timestamp = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    completion_timestamp = Column(DateTime(timezone=True), nullable=True)
    summary = Column(JSON, default=dict, nullable=False)
    scanner_version = Column(String(32), default="1.0.0", nullable=False)

    # Relationships
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


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


class SecurityTestCase(Base):
    """Database model for structured security test cases."""

    __tablename__ = "security_test_cases"

    id = Column(String(64), primary_key=True)
    category = Column(String(64), nullable=False, index=True)
    test_input = Column(Text, nullable=False)
    expected_behavior = Column(String(128), nullable=False)
    expected_outcome = Column(String(128), default="", nullable=False)
    test_rationale = Column(Text, default="", nullable=False)
    enabled = Column(Boolean, default=True, nullable=False, index=True)
    metadata_json = Column(JSON, default=dict, nullable=False)


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

"""Unit tests for report generation, JSON formatting, and CSV formula injection protection."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.connection import Base
from app.database.models import Finding
from app.database.repository import FindingRepository, ScanRepository
from app.reports.export import export_findings_to_csv, export_report_to_json, sanitize_csv_cell
from app.reports.generator import ReportGenerator


@pytest.fixture
def db_session():
    """In-memory SQLite session."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine)
    session = TestingSession()
    try:
        yield session
    finally:
        session.close()


def test_sanitize_csv_cell_formula_injection_defense():
    """Verify spreadsheet formula injection payloads (CWE-1236) are sanitized."""
    # Test formula characters =, +, -, @, tab, newline
    assert sanitize_csv_cell("=1+1") == "'=1+1"
    assert sanitize_csv_cell("+cmd|' /C calc'!A0") == "'+cmd|' /C calc'!A0"
    assert sanitize_csv_cell("-2+3") == "'-2+3"
    assert sanitize_csv_cell("@SUM(A1:A10)") == "'@SUM(A1:A10)"
    assert sanitize_csv_cell("\tDDE_ATTACK") == "'\tDDE_ATTACK"

    # Benign text must remain unchanged
    assert sanitize_csv_cell("Direct prompt injection") == "Direct prompt injection"
    assert sanitize_csv_cell(None) == ""
    assert sanitize_csv_cell("") == ""


def test_export_findings_to_csv_sanitizes_malicious_finding():
    """Verify CSV export sanitizes malicious payloads stored inside finding titles/descriptions."""
    finding = Finding(
        id="FIND-01",
        scan_id="SCAN-01",
        category="prompt_injection",
        severity="HIGH",
        title="=HYPERLINK('http://malicious.site','Click Here')",
        description="+cmd.exe /c calc",
        target_component="input",
        affected_test_case="PI-001",
        detection_method="ml",
        remediation="Strict validation",
        retest_status="NOT_RETESTED",
    )

    csv_output = export_findings_to_csv([finding])
    assert "Finding ID,Category,Severity,Title" in csv_output
    # Must be sanitized with leading quote
    assert "'=HYPERLINK" in csv_output
    assert "'+cmd.exe" in csv_output


def test_report_generator_structured_output(db_session):
    """Verify ReportGenerator generates complete report conforming to reporting standards."""
    scan = ScanRepository.create_scan(
        db=db_session,
        target_identifier="http://127.0.0.1:8000/api/v1/demo-rag/query",
        configuration={"timeout": 10.0},
    )
    ScanRepository.update_scan_status(
        db=db_session,
        scan_id=scan.id,
        status="COMPLETED",
        summary={"total_tests": 5, "tests_passed": 4, "tests_failed": 1},
    )
    FindingRepository.create_finding(
        db=db_session,
        scan_id=scan.id,
        category="data_leakage",
        severity="CRITICAL",
        title="Database Password Disclosed",
        description="Leaked synthetic database master password",
        evidence={"canary": "CANARY_SEC_TOKEN_9981"},
        confidence_score=0.98,
        remediation="Enable output guardrail canary redaction",
    )

    report = ReportGenerator.generate_report(db=db_session, scan_id=scan.id)
    assert report.scan_id == scan.id
    assert report.total_tests == 5
    assert report.tests_failed == 1
    assert len(report.findings) == 1
    assert report.findings_by_severity.get("CRITICAL") == 1
    assert len(report.remediation_recommendations) == 1
    assert len(report.evaluation_limitations) >= 3

    json_str = export_report_to_json(report.model_dump())
    assert scan.id in json_str
    assert "evaluation_limitations" in json_str

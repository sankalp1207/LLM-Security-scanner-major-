"""Scan management, presets, and test telemetry route endpoints."""

from typing import List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.schemas.presets import ScanPresetConfig, list_presets
from app.schemas.scans import (
    FindingResponse,
    ScanCancelRequest,
    ScanCreateRequest,
    ScanListResponse,
    ScanResponse,
    TestExecutionListResponse,
)
from app.services.scan_service import ScanService

router = APIRouter(prefix="/scans", tags=["Scans"])
scan_engine_router = APIRouter(prefix="/scan", tags=["Scan Presets"])


def get_current_user_id(x_user_id: Optional[str] = Header(None)) -> str:
    """Extract authenticated user identity or default for development."""
    return (x_user_id or "default_user").strip()


# -----------------------------------------------------------------------------
# PRESETS (Available via /scan/presets and /scans/presets)
# -----------------------------------------------------------------------------
@scan_engine_router.get("/presets", response_model=List[ScanPresetConfig])
@router.get("/presets", response_model=List[ScanPresetConfig])
def get_presets() -> List[ScanPresetConfig]:
    """Retrieve canonical server-side scan presets (Quick Scan, Full Scan, Deep Red Team)."""
    return list_presets()


# -----------------------------------------------------------------------------
# LEGACY & DIRECT SCAN CREATION
# -----------------------------------------------------------------------------
@router.post("", response_model=ScanResponse)
def create_scan(
    request: ScanCreateRequest,
    db: Session = Depends(get_db),
) -> ScanResponse:
    """Validate, create, and execute a security scan against the configured target."""
    scan = ScanService.create_and_run_scan(db=db, request=request)
    findings = ScanService.get_findings_for_scan(db=db, scan_id=scan.id)
    return ScanResponse(
        id=scan.id,
        project_id=scan.project_id,
        user_id=scan.user_id,
        preset=scan.preset,
        target_identifier=scan.target_identifier,
        status=scan.status,
        configuration=scan.configuration,
        configuration_snapshot=scan.configuration_snapshot,
        start_timestamp=scan.start_timestamp.isoformat(),
        completion_timestamp=scan.completion_timestamp.isoformat() if scan.completion_timestamp else None,
        summary=scan.summary,
        scanner_version=scan.scanner_version,
        findings_count=len(findings),
        total_tests=scan.total_tests,
        completed_tests=scan.completed_tests,
        passed_tests=scan.passed_tests,
        failed_tests=scan.failed_tests,
        inconclusive_tests=scan.inconclusive_tests,
        skipped_tests=scan.skipped_tests,
        execution_errors=scan.execution_errors,
        cancellation_reason=scan.cancellation_reason,
        failure_reason=scan.failure_reason,
    )


@router.get("", response_model=ScanListResponse)
def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
) -> ScanListResponse:
    """List recent scan executions with pagination."""
    scans = ScanService.list_scans(db=db, skip=skip, limit=limit)
    items = []
    for s in scans:
        findings = ScanService.get_findings_for_scan(db=db, scan_id=s.id)
        items.append(
            ScanResponse(
                id=s.id,
                project_id=s.project_id,
                user_id=s.user_id,
                preset=s.preset,
                target_identifier=s.target_identifier,
                status=s.status,
                configuration=s.configuration,
                configuration_snapshot=s.configuration_snapshot,
                start_timestamp=s.start_timestamp.isoformat(),
                completion_timestamp=s.completion_timestamp.isoformat() if s.completion_timestamp else None,
                summary=s.summary,
                scanner_version=s.scanner_version,
                findings_count=len(findings),
                total_tests=s.total_tests,
                completed_tests=s.completed_tests,
                passed_tests=s.passed_tests,
                failed_tests=s.failed_tests,
                inconclusive_tests=s.inconclusive_tests,
                skipped_tests=s.skipped_tests,
                execution_errors=s.execution_errors,
                cancellation_reason=s.cancellation_reason,
                failure_reason=s.failure_reason,
            )
        )
    return ScanListResponse(total=len(items), items=items)


# -----------------------------------------------------------------------------
# SCAN DETAILS, TESTS & FINDINGS
# -----------------------------------------------------------------------------
@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: str,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> ScanResponse:
    """Retrieve details and summary for a single scan under authorized user identity."""
    scan = ScanService.get_scan(db=db, scan_id=scan_id, user_id=user_id)
    findings = ScanService.get_findings_for_scan(db=db, scan_id=scan.id, user_id=user_id)
    return ScanResponse(
        id=scan.id,
        project_id=scan.project_id,
        user_id=scan.user_id,
        preset=scan.preset,
        target_identifier=scan.target_identifier,
        status=scan.status,
        configuration=scan.configuration,
        configuration_snapshot=scan.configuration_snapshot,
        start_timestamp=scan.start_timestamp.isoformat(),
        completion_timestamp=scan.completion_timestamp.isoformat() if scan.completion_timestamp else None,
        summary=scan.summary,
        scanner_version=scan.scanner_version,
        findings_count=len(findings),
        total_tests=scan.total_tests,
        completed_tests=scan.completed_tests,
        passed_tests=scan.passed_tests,
        failed_tests=scan.failed_tests,
        inconclusive_tests=scan.inconclusive_tests,
        skipped_tests=scan.skipped_tests,
        execution_errors=scan.execution_errors,
        cancellation_reason=scan.cancellation_reason,
        failure_reason=scan.failure_reason,
    )


@router.get("/{scan_id}/tests", response_model=TestExecutionListResponse)
def get_scan_tests(
    scan_id: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=200),
    status: Optional[str] = Query(None, description="Filter by status: PASSED, FAILED, INCONCLUSIVE, SKIPPED, ERROR"),
    category: Optional[str] = Query(None, description="Filter by threat category"),
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> TestExecutionListResponse:
    """Retrieve paginated individual test execution records and telemetry for a scan."""
    return ScanService.get_scan_test_executions(
        db=db,
        scan_id=scan_id,
        user_id=user_id,
        skip=skip,
        limit=limit,
        status=status,
        category=category,
    )


@router.get("/{scan_id}/findings", response_model=List[FindingResponse])
def get_scan_findings(
    scan_id: str,
    category: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> List[FindingResponse]:
    """Retrieve findings identified in a specific scan with optional filtering."""
    findings = ScanService.get_findings_for_scan(
        db=db, scan_id=scan_id, category=category, severity=severity, user_id=user_id
    )
    return [
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


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
def cancel_scan(
    scan_id: str,
    request: Optional[ScanCancelRequest] = None,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> ScanResponse:
    """Request safe cancellation of an active or queued scan."""
    reason = request.reason if request and request.reason else "Cancelled by user"
    scan = ScanService.cancel_scan(db=db, scan_id=scan_id, user_id=user_id, reason=reason)
    findings = ScanService.get_findings_for_scan(db=db, scan_id=scan.id, user_id=user_id)
    return ScanResponse(
        id=scan.id,
        project_id=scan.project_id,
        user_id=scan.user_id,
        preset=scan.preset,
        target_identifier=scan.target_identifier,
        status=scan.status,
        configuration=scan.configuration,
        configuration_snapshot=scan.configuration_snapshot,
        start_timestamp=scan.start_timestamp.isoformat(),
        completion_timestamp=scan.completion_timestamp.isoformat() if scan.completion_timestamp else None,
        summary=scan.summary,
        scanner_version=scan.scanner_version,
        findings_count=len(findings),
        total_tests=scan.total_tests,
        completed_tests=scan.completed_tests,
        passed_tests=scan.passed_tests,
        failed_tests=scan.failed_tests,
        inconclusive_tests=scan.inconclusive_tests,
        skipped_tests=scan.skipped_tests,
        execution_errors=scan.execution_errors,
        cancellation_reason=scan.cancellation_reason,
        failure_reason=scan.failure_reason,
    )

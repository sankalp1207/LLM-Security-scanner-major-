"""Scan management route endpoints."""

from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.schemas.scans import (
    FindingResponse,
    ScanCreateRequest,
    ScanListResponse,
    ScanResponse,
)
from app.services.scan_service import ScanService

router = APIRouter(prefix="/scans", tags=["Scans"])


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
        target_identifier=scan.target_identifier,
        status=scan.status,
        configuration=scan.configuration,
        start_timestamp=scan.start_timestamp.isoformat(),
        completion_timestamp=scan.completion_timestamp.isoformat() if scan.completion_timestamp else None,
        summary=scan.summary,
        scanner_version=scan.scanner_version,
        findings_count=len(findings),
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
                target_identifier=s.target_identifier,
                status=s.status,
                configuration=s.configuration,
                start_timestamp=s.start_timestamp.isoformat(),
                completion_timestamp=s.completion_timestamp.isoformat() if s.completion_timestamp else None,
                summary=s.summary,
                scanner_version=s.scanner_version,
                findings_count=len(findings),
            )
        )
    return ScanListResponse(total=len(items), items=items)


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
) -> ScanResponse:
    """Retrieve details and summary for a single scan."""
    scan = ScanService.get_scan(db=db, scan_id=scan_id)
    findings = ScanService.get_findings_for_scan(db=db, scan_id=scan.id)
    return ScanResponse(
        id=scan.id,
        target_identifier=scan.target_identifier,
        status=scan.status,
        configuration=scan.configuration,
        start_timestamp=scan.start_timestamp.isoformat(),
        completion_timestamp=scan.completion_timestamp.isoformat() if scan.completion_timestamp else None,
        summary=scan.summary,
        scanner_version=scan.scanner_version,
        findings_count=len(findings),
    )


@router.get("/{scan_id}/findings", response_model=List[FindingResponse])
def get_scan_findings(
    scan_id: str,
    category: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    db: Session = Depends(get_db),
) -> List[FindingResponse]:
    """Retrieve findings identified in a specific scan with optional filtering."""
    findings = ScanService.get_findings_for_scan(
        db=db, scan_id=scan_id, category=category, severity=severity
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

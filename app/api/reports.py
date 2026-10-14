"""Report generation and CSV export route handlers."""

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.database.repository import FindingRepository, ScanRepository
from app.reports.export import export_findings_to_csv
from app.reports.generator import ReportGenerator
from app.schemas.reports import ScanReportResponse

router = APIRouter(prefix="/scans", tags=["Reports"])


@router.get("/{scan_id}/report", response_model=ScanReportResponse)
def get_scan_report(
    scan_id: str,
    db: Session = Depends(get_db),
) -> ScanReportResponse:
    """Generate and return a structured JSON security audit report for a completed scan."""
    try:
        return ReportGenerator.generate_report(db=db, scan_id=scan_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e


@router.get("/{scan_id}/export.csv")
def export_scan_csv(
    scan_id: str,
    db: Session = Depends(get_db),
) -> Response:
    """Export findings for a scan as a sanitized CSV spreadsheet (protected against CSV injection)."""
    scan = ScanRepository.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")

    findings = FindingRepository.list_findings_by_scan(db, scan_id=scan_id)
    csv_content = export_findings_to_csv(findings)

    filename = f"scan_report_{scan_id[:8]}.csv"
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

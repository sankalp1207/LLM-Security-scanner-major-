"""Integration tests for Report and CSV Export API endpoints."""

from fastapi.testclient import TestClient


def test_get_scan_report_and_csv_export(client: TestClient):
    """Verify JSON report and CSV export endpoints return valid formats and headers."""
    # 1. Create a scan
    payload = {
        "target_url": "http://testserver/api/v1/demo-rag/query",
        "categories": ["prompt_injection"],
        "max_concurrency": 2,
        "timeout_seconds": 5.0,
    }
    res_create = client.post("/api/v1/scans", json=payload)
    assert res_create.status_code == 200
    scan_id = res_create.json()["id"]

    # 2. Get JSON report
    res_report = client.get(f"/api/v1/scans/{scan_id}/report")
    assert res_report.status_code == 200
    report_data = res_report.json()
    assert report_data["scan_id"] == scan_id
    assert "findings_by_severity" in report_data
    assert "evaluation_limitations" in report_data
    assert isinstance(report_data["remediation_recommendations"], list)

    # 3. Get CSV export
    res_csv = client.get(f"/api/v1/scans/{scan_id}/export.csv")
    assert res_csv.status_code == 200
    assert "text/csv" in res_csv.headers.get("content-type", "")
    assert "attachment" in res_csv.headers.get("content-disposition", "")
    assert "Finding ID,Category,Severity,Title" in res_csv.text


def test_report_nonexistent_scan_returns_404(client: TestClient):
    """Verify 404 is returned when requesting report for unknown scan."""
    response = client.get("/api/v1/scans/non-existent-scan-id/report")
    assert response.status_code == 404

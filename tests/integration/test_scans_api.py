"""Integration tests for Scans and Findings API endpoints."""

from fastapi.testclient import TestClient


def test_create_and_retrieve_scan(client: TestClient):
    """Verify initiating a scan against local demo target and fetching details & findings."""
    # 1. Trigger scan
    payload = {
        "target_url": "http://testserver/api/v1/demo-rag/query",
        "categories": ["prompt_injection", "data_leakage"],
        "max_concurrency": 2,
        "timeout_seconds": 5.0,
    }
    res_create = client.post("/api/v1/scans", json=payload)
    assert res_create.status_code == 200
    scan_data = res_create.json()
    assert "id" in scan_data
    scan_id = scan_data["id"]
    assert scan_data["status"] in ("COMPLETED", "PARTIALLY_COMPLETED", "RUNNING")

    # 2. Retrieve scan details
    res_get = client.get(f"/api/v1/scans/{scan_id}")
    assert res_get.status_code == 200
    assert res_get.json()["id"] == scan_id

    # 3. Retrieve findings for the scan
    res_findings = client.get(f"/api/v1/scans/{scan_id}/findings")
    assert res_findings.status_code == 200
    findings = res_findings.json()
    assert isinstance(findings, list)

    # 4. If findings exist, test finding details and retest endpoint
    if findings:
        f_id = findings[0]["id"]
        res_single_f = client.get(f"/api/v1/findings/{f_id}")
        assert res_single_f.status_code == 200
        assert res_single_f.json()["id"] == f_id

        # Retest finding
        res_retest = client.post(f"/api/v1/findings/{f_id}/retest")
        assert res_retest.status_code == 200
        assert "retest_status" in res_retest.json()


def test_list_scans_pagination(client: TestClient):
    """Verify paginated listing of scans."""
    response = client.get("/api/v1/scans?skip=0&limit=10")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "items" in data
    assert isinstance(data["items"], list)


def test_list_all_findings_endpoint(client: TestClient):
    """Verify listing findings across all scans with optional filtering."""
    response = client.get("/api/v1/findings?skip=0&limit=20")
    assert response.status_code == 200
    findings = response.json()
    assert isinstance(findings, list)

    # Test with filters
    response_filt = client.get("/api/v1/findings?severity=CRITICAL&limit=5")
    assert response_filt.status_code == 200
    assert isinstance(response_filt.json(), list)

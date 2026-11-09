"""Integration tests for One-Click Scanning, Presets, Capabilities, and Test Execution Telemetry APIs."""

import uuid
from fastapi.testclient import TestClient


def test_scan_presets_api_endpoints(client: TestClient):
    """Verify both /api/v1/scan/presets and /api/v1/scans/presets return canonical presets."""
    for endpoint in ("/api/v1/scan/presets", "/api/v1/scans/presets"):
        res = client.get(endpoint)
        assert res.status_code == 200
        data = res.json()
        assert isinstance(data, list)
        assert len(data) >= 3

        ids = [p["preset_id"] for p in data]
        assert "quick_scan" in ids
        assert "full_scan" in ids
        assert "deep_red_team" in ids


def test_project_capabilities_api(client: TestClient):
    """Verify resolving target capabilities for a newly provisioned project."""
    headers = {"x-user-id": f"cap_user_{uuid.uuid4().hex[:8]}"}

    # Create chatbot project
    res_p = client.post(
        "/api/v1/projects",
        json={
            "name": f"Chatbot Target {uuid.uuid4().hex[:6]}",
            "application_type": "chatbot",
            "environment": "development",
            "target_type": "local_llm",
            "target_configuration": {
                "provider": "ollama",
                "endpoint_url": "http://127.0.0.1:11434/api/generate",
            },
        },
        headers=headers,
    )
    assert res_p.status_code == 200
    pid = res_p.json()["id"]

    try:
        res_cap = client.get(f"/api/v1/projects/{pid}/scan-capabilities", headers=headers)
        assert res_cap.status_code == 200
        cap_data = res_cap.json()

        assert "chat_completion" in cap_data["detected_capabilities"]
        assert "rag_retrieval" not in cap_data["detected_capabilities"]
        assert cap_data["category_support"]["prompt_injection"]["is_applicable"] is True
        assert cap_data["category_support"]["indirect_prompt_injection"]["is_applicable"] is False
        assert any(s["category"] == "indirect_prompt_injection" for s in cap_data["skipped_categories"])
    finally:
        client.delete(f"/api/v1/projects/{pid}", headers=headers)


def test_one_click_quick_scan_workflow(client: TestClient):
    """Verify full end-to-end execution of Quick Scan preset against local demo target."""
    headers = {"x-user-id": f"scan_user_{uuid.uuid4().hex[:8]}"}

    # 1. Create project
    res_p = client.post(
        "/api/v1/projects",
        json={
            "name": f"Demo Quick Scan Project {uuid.uuid4().hex[:6]}",
            "application_type": "rag",
            "environment": "development",
            "target_type": "demo",
            "target_configuration": {
                "provider": "demo",
                "endpoint_url": "http://testserver/api/v1/demo-rag/query",
            },
        },
        headers=headers,
    )
    assert res_p.status_code == 200
    pid = res_p.json()["id"]

    try:
        # 2. Trigger One-Click Quick Scan with synchronous completion
        scan_payload = {
            "preset": "quick_scan",
            "custom_max_tests": 8,
            "sync_execute": True,
        }
        res_scan = client.post(f"/api/v1/projects/{pid}/scans", json=scan_payload, headers=headers)
        assert res_scan.status_code == 200
        scan_data = res_scan.json()

        scan_id = scan_data["id"]
        assert scan_data["project_id"] == pid
        assert scan_data["preset"] == "quick_scan"
        assert scan_data["status"] in ("COMPLETED", "PARTIALLY_COMPLETED")
        assert scan_data["total_tests"] > 0
        assert scan_data["completed_tests"] > 0

        # 3. Retrieve individual test execution telemetry
        res_tests = client.get(f"/api/v1/scans/{scan_id}/tests", headers=headers)
        assert res_tests.status_code == 200
        tests_data = res_tests.json()
        assert tests_data["total"] > 0
        assert len(tests_data["items"]) > 0

        first_test = tests_data["items"][0]
        assert "test_case_id" in first_test
        assert "category" in first_test
        assert first_test["execution_status"] in ("PASSED", "FAILED", "INCONCLUSIVE", "ERROR")
        assert "latency_ms" in first_test

        # 4. Filter test executions by status
        res_filtered = client.get(f"/api/v1/scans/{scan_id}/tests?status=PASSED", headers=headers)
        assert res_filtered.status_code == 200
        for item in res_filtered.json()["items"]:
            assert item["execution_status"] == "PASSED"

        # 5. Retrieve scan details
        res_get = client.get(f"/api/v1/scans/{scan_id}", headers=headers)
        assert res_get.status_code == 200
        assert res_get.json()["id"] == scan_id

        # 6. Retrieve scan findings
        res_findings = client.get(f"/api/v1/scans/{scan_id}/findings", headers=headers)
        assert res_findings.status_code == 200
        assert isinstance(res_findings.json(), list)

        # 7. List scans for project
        res_list = client.get(f"/api/v1/projects/{pid}/scans", headers=headers)
        assert res_list.status_code == 200
        assert res_list.json()["total"] >= 1
    finally:
        client.delete(f"/api/v1/projects/{pid}", headers=headers)


def test_deep_red_team_preset_mutation_fuzzing(client: TestClient):
    """Verify Deep Red Team preset activates adversarial mutation fuzzing."""
    headers = {"x-user-id": f"red_team_user_{uuid.uuid4().hex[:8]}"}

    res_p = client.post(
        "/api/v1/projects",
        json={
            "name": f"Red Team Audit {uuid.uuid4().hex[:6]}",
            "application_type": "rag",
            "environment": "testing",
            "target_type": "demo",
            "target_configuration": {
                "provider": "demo",
                "endpoint_url": "http://testserver/api/v1/demo-rag/query",
            },
        },
        headers=headers,
    )
    assert res_p.status_code == 200
    pid = res_p.json()["id"]

    try:
        res_scan = client.post(
            f"/api/v1/projects/{pid}/scans",
            json={
                "preset": "deep_red_team",
                "custom_max_tests": 6,
                "sync_execute": True,
            },
            headers=headers,
        )
        assert res_scan.status_code == 200
        scan_data = res_scan.json()
        assert scan_data["preset"] == "deep_red_team"
        summary = scan_data.get("summary", {})
        assert summary.get("mutation_fuzzing_enabled") is True
    finally:
        client.delete(f"/api/v1/projects/{pid}", headers=headers)


def test_external_target_requires_authorization_acknowledgement(client: TestClient):
    """Verify that targeting an external destination rejects scanning without explicit authorization acknowledgement."""
    headers = {"x-user-id": f"ext_user_{uuid.uuid4().hex[:8]}"}

    res_p = client.post(
        "/api/v1/projects",
        json={
            "name": f"External API Target {uuid.uuid4().hex[:6]}",
            "application_type": "api",
            "environment": "production",
            "target_type": "external_api",
            "target_configuration": {
                "provider": "openai_compatible",
                "endpoint_url": "https://api.external-ai.com/v1/chat",
            },
        },
        headers=headers,
    )
    assert res_p.status_code == 200
    pid = res_p.json()["id"]

    try:
        # Without authorization acknowledgement -> must fail with 400
        res_unauth = client.post(
            f"/api/v1/projects/{pid}/scans",
            json={"preset": "quick_scan", "external_target_authorized": False},
            headers=headers,
        )
        assert res_unauth.status_code == 400
        assert "authorization" in res_unauth.json()["detail"].lower()
    finally:
        client.delete(f"/api/v1/projects/{pid}", headers=headers)


def test_ssrf_prohibited_destination_blocked(client: TestClient):
    """Verify that cloud metadata targets are rejected by pre-flight validation."""
    headers = {"x-user-id": f"ssrf_user_{uuid.uuid4().hex[:8]}"}

    res_p = client.post(
        "/api/v1/projects",
        json={
            "name": f"Malicious Metadata Target {uuid.uuid4().hex[:6]}",
            "application_type": "api",
            "environment": "development",
            "target_type": "external_api",
            "target_configuration": {
                "provider": "openai_compatible",
                "endpoint_url": "http://169.254.169.254/latest/meta-data",
            },
        },
        headers=headers,
    )
    assert res_p.status_code == 200
    pid = res_p.json()["id"]

    try:
        res_scan = client.post(
            f"/api/v1/projects/{pid}/scans",
            json={"preset": "quick_scan", "external_target_authorized": True},
            headers=headers,
        )
        assert res_scan.status_code == 400
        assert "security policy" in res_scan.json()["detail"].lower() or "ssrf" in res_scan.json()["detail"].lower()
    finally:
        client.delete(f"/api/v1/projects/{pid}", headers=headers)


def test_scan_cancellation_api(client: TestClient):
    """Verify cancelling an existing scan via the /scans/{id}/cancel endpoint."""
    headers = {"x-user-id": f"cancel_api_user_{uuid.uuid4().hex[:8]}"}

    res_p = client.post(
        "/api/v1/projects",
        json={
            "name": f"Cancel Test Project {uuid.uuid4().hex[:6]}",
            "application_type": "rag",
            "environment": "development",
            "target_type": "demo",
            "target_configuration": {
                "provider": "demo",
                "endpoint_url": "http://testserver/api/v1/demo-rag/query",
            },
        },
        headers=headers,
    )
    assert res_p.status_code == 200
    pid = res_p.json()["id"]

    try:
        # Create completed scan
        res_scan = client.post(
            f"/api/v1/projects/{pid}/scans",
            json={"preset": "quick_scan", "custom_max_tests": 4, "sync_execute": True},
            headers=headers,
        )
        assert res_scan.status_code == 200
        scan_id = res_scan.json()["id"]

        # Request cancellation
        res_cancel = client.post(
            f"/api/v1/scans/{scan_id}/cancel",
            json={"reason": "User requested abort"},
            headers=headers,
        )
        assert res_cancel.status_code == 200
    finally:
        client.delete(f"/api/v1/projects/{pid}", headers=headers)


def test_project_scan_ownership_isolation(client: TestClient):
    """Verify that a user cannot launch or list scans for another user's project."""
    user_a = {"x-user-id": f"user_a_{uuid.uuid4().hex[:8]}"}
    user_b = {"x-user-id": f"user_b_{uuid.uuid4().hex[:8]}"}

    # User A creates project
    res_p = client.post(
        "/api/v1/projects",
        json={
            "name": f"Isolated Project {uuid.uuid4().hex[:6]}",
            "application_type": "rag",
            "target_type": "demo",
            "target_configuration": {
                "provider": "demo",
                "endpoint_url": "http://testserver/api/v1/demo-rag/query",
            },
        },
        headers=user_a,
    )
    assert res_p.status_code == 200
    pid = res_p.json()["id"]

    try:
        # User B attempts to list scans -> receives 404
        res_list = client.get(f"/api/v1/projects/{pid}/scans", headers=user_b)
        assert res_list.status_code == 404

        # User B attempts to launch scan -> receives 403 or 404
        res_scan = client.post(
            f"/api/v1/projects/{pid}/scans",
            json={"preset": "quick_scan"},
            headers=user_b,
        )
        assert res_scan.status_code in (403, 404)
    finally:
        client.delete(f"/api/v1/projects/{pid}", headers=user_a)

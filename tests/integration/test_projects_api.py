"""Integration tests for Project Management, Target Verification, and Onboarding APIs."""

from fastapi.testclient import TestClient


def test_onboarding_api_flow(client: TestClient):
    """Verify onboarding status check, completion, and reset endpoints."""
    headers = {"x-user-id": "test_onboarding_user_api"}

    # 1. Initial status
    res = client.get("/api/v1/onboarding/status", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["is_completed"] is False

    # 2. Complete onboarding
    res_comp = client.post(
        "/api/v1/onboarding/complete",
        json={"selected_demo": True, "project_id": "test-pid"},
        headers=headers,
    )
    assert res_comp.status_code == 200
    assert res_comp.json()["is_completed"] is True
    assert res_comp.json()["selected_demo"] is True

    # 3. Verify status persisted
    res_check = client.get("/api/v1/onboarding/status", headers=headers)
    assert res_check.status_code == 200
    assert res_check.json()["is_completed"] is True

    # 4. Reset onboarding
    res_reset = client.post("/api/v1/onboarding/reset", headers=headers)
    assert res_reset.status_code == 200
    assert res_reset.json()["is_completed"] is False


def test_project_crud_lifecycle_and_credential_masking(client: TestClient):
    """Verify project creation with credential encryption, masking, update, and deletion."""
    headers = {"x-user-id": "test_crud_user"}
    raw_secret = "sk-live-super-secret-production-token-8844"

    payload = {
        "name": "Customer Support RAG Staging",
        "description": "Production candidate customer assistant",
        "application_type": "rag",
        "environment": "staging",
        "target_type": "external_api",
        "target_configuration": {
            "provider": "openai_compatible",
            "endpoint_url": "https://api.external-ai.com/v1/query",
            "model_identifier": "gpt-4o-mini",
            "auth_type": "bearer",
            "credential": raw_secret,
            "connection_timeout": 8.0,
        },
        "default_scan_preferences": {
            "direct_prompt_injection": True,
            "scan_preference": "deep_red_team",
        },
    }

    # 1. Create Project
    res = client.post("/api/v1/projects", json=payload, headers=headers)
    assert res.status_code == 200
    p = res.json()
    project_id = p["id"]
    assert p["name"] == payload["name"]
    assert p["environment"] == "staging"

    # Verify secret is masked and NEVER returned in plaintext
    tc = p["target_configuration"]
    assert tc is not None
    assert tc["masked_credential"] != ""
    assert raw_secret not in tc["masked_credential"]
    assert "••••••••" in tc["masked_credential"]

    # 2. Get Project
    res_get = client.get(f"/api/v1/projects/{project_id}", headers=headers)
    assert res_get.status_code == 200
    p_get = res_get.json()
    assert p_get["id"] == project_id
    assert raw_secret not in str(p_get)

    # 3. Update Project
    update_payload = {
        "description": "Updated staging description",
        "environment": "production",
    }
    res_patch = client.patch(f"/api/v1/projects/{project_id}", json=update_payload, headers=headers)
    assert res_patch.status_code == 200
    assert res_patch.json()["description"] == "Updated staging description"
    assert res_patch.json()["environment"] == "production"

    # 4. List Projects
    res_list = client.get("/api/v1/projects", headers=headers)
    assert res_list.status_code == 200
    assert res_list.json()["total"] >= 1
    assert any(item["id"] == project_id for item in res_list.json()["items"])

    # 5. Delete Project
    res_del = client.delete(f"/api/v1/projects/{project_id}", headers=headers)
    assert res_del.status_code == 200
    assert res_del.json()["status"] == "deleted"

    # Confirm 404 after deletion
    res_after = client.get(f"/api/v1/projects/{project_id}", headers=headers)
    assert res_after.status_code == 404


def test_duplicate_project_name_rejection(client: TestClient):
    """Verify that creating two projects with duplicate names in the same user scope is rejected with 400."""
    headers = {"x-user-id": "dup_test_user"}
    payload = {
        "name": "Unique Project Scope Alpha",
        "description": "First instance",
        "application_type": "chatbot",
        "environment": "development",
        "target_type": "demo",
    }

    # First succeeds
    res1 = client.post("/api/v1/projects", json=payload, headers=headers)
    assert res1.status_code == 200
    pid = res1.json()["id"]

    try:
        # Second with identical name fails
        res2 = client.post("/api/v1/projects", json=payload, headers=headers)
        assert res2.status_code == 400
        assert "already exists" in res2.json()["detail"].lower()
    finally:
        client.delete(f"/api/v1/projects/{pid}", headers=headers)


def test_project_ownership_isolation(client: TestClient):
    """Verify that users cannot view or delete another user's project."""
    user_a = {"x-user-id": "tenant_alice"}
    user_b = {"x-user-id": "tenant_bob"}

    # Alice creates a project
    res_a = client.post(
        "/api/v1/projects",
        json={"name": "Alice Private Project", "target_type": "demo"},
        headers=user_a,
    )
    assert res_a.status_code == 200
    alice_pid = res_a.json()["id"]

    try:
        # Bob cannot access Alice's project
        res_b_get = client.get(f"/api/v1/projects/{alice_pid}", headers=user_b)
        assert res_b_get.status_code == 404

        # Bob cannot delete Alice's project
        res_b_del = client.delete(f"/api/v1/projects/{alice_pid}", headers=user_b)
        assert res_b_del.status_code == 404
    finally:
        # Alice cleans up
        client.delete(f"/api/v1/projects/{alice_pid}", headers=user_a)


def test_project_connection_verification_demo(client: TestClient):
    """Verify live connection verification on local demo project."""
    headers = {"x-user-id": "test_conn_user"}
    res_p = client.post(
        "/api/v1/projects",
        json={
            "name": "Demo Target Project",
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
        res_ver = client.post(f"/api/v1/projects/{pid}/verify-connection", headers=headers)
        assert res_ver.status_code == 200
        data = res_ver.json()
        assert data["is_connected"] is True
        assert data["status"] == "CONNECTED"
    finally:
        client.delete(f"/api/v1/projects/{pid}", headers=headers)


def test_project_connection_verification_ssrf_blocked(client: TestClient):
    """Verify connection verification blocks SSRF probes to cloud metadata."""
    headers = {"x-user-id": "test_ssrf_user"}
    res_p = client.post(
        "/api/v1/projects",
        json={
            "name": "SSRF Target Project",
            "target_type": "external_api",
            "target_configuration": {
                "provider": "generic_http",
                "endpoint_url": "http://169.254.169.254/latest/meta-data",
            },
        },
        headers=headers,
    )
    assert res_p.status_code == 200
    pid = res_p.json()["id"]

    try:
        res_ver = client.post(f"/api/v1/projects/{pid}/verify-connection", headers=headers)
        assert res_ver.status_code == 200
        data = res_ver.json()
        assert data["is_connected"] is False
        assert data["status"] == "BLOCKED"
        assert "ssrf" in data["message"].lower() or "metadata" in data["message"].lower()
    finally:
        client.delete(f"/api/v1/projects/{pid}", headers=headers)


def test_project_preferences_api(client: TestClient):
    """Verify retrieving and updating project security preferences."""
    headers = {"x-user-id": "pref_test_user"}
    res_p = client.post(
        "/api/v1/projects",
        json={"name": "Pref Test Project", "target_type": "demo"},
        headers=headers,
    )
    assert res_p.status_code == 200
    pid = res_p.json()["id"]

    try:
        # Get preferences
        res_get = client.get(f"/api/v1/projects/{pid}/preferences", headers=headers)
        assert res_get.status_code == 200
        prefs = res_get.json()
        assert prefs.get("direct_prompt_injection") is True

        # Patch preferences
        new_prefs = {"scan_preference": "quick", "agent_security": True}
        res_patch = client.patch(f"/api/v1/projects/{pid}/preferences", json=new_prefs, headers=headers)
        assert res_patch.status_code == 200
        updated = res_patch.json()["preferences"]
        assert updated["scan_preference"] == "quick"
        assert updated["agent_security"] is True
    finally:
        client.delete(f"/api/v1/projects/{pid}", headers=headers)


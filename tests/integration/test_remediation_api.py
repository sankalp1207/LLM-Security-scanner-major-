"""Integration tests for Phase 6 Automated Remediation Assistant API endpoints and security gates."""

from pathlib import Path
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database.models import Finding, Project, Scan
from app.database.repository import (
    FindingRepository,
    ProjectRepository,
    ScanRepository,
)


def test_remediation_initiate_and_user_isolation(client: TestClient, db_session: Session):
    """Verify remediation initiation and strict tenant isolation."""
    user_a = f"rem_user_a_{uuid.uuid4().hex[:8]}"
    user_b = f"rem_user_b_{uuid.uuid4().hex[:8]}"
    headers_a = {"x-user-id": user_a}
    headers_b = {"x-user-id": user_b}

    proj = ProjectRepository.create_project(
        db=db_session,
        name="Remediation Isolated Project",
        application_type="rag",
        environment="development",
        target_type="demo",
        owner_id=user_a,
    )
    scan = ScanRepository.create_scan(
        db=db_session,
        target_identifier="http://testserver/api/v1/demo-rag/query",
        configuration={"preset": "quick_scan"},
        project_id=proj.id,
        user_id=user_a,
        preset="quick_scan",
        status="COMPLETED",
    )
    finding = FindingRepository.create_finding(
        db=db_session,
        scan_id=scan.id,
        category="prompt_injection",
        severity="HIGH",
        title="Direct Prompt Injection Vulnerability",
        description="Override system directives",
        evidence={"input_snippet": "ignore instructions"},
        affected_test_case="direct_01",
        target_component="app/demo_rag/routes.py",
    )

    # 1. User A initiates remediation
    res = client.post(f"/api/v1/remediations/findings/{finding.id}", headers=headers_a)
    assert res.status_code == 200
    rem_data = res.json()
    rem_id = rem_data["id"]
    assert rem_data["finding_id"] == finding.id
    assert rem_data["user_id"] == user_a
    assert rem_data["status"] in ("AWAITING_APPROVAL", "FIX_PROPOSED", "ANALYZING")

    # 2. User B cannot access User A's remediation
    res_unauth = client.get(f"/api/v1/remediations/{rem_id}", headers=headers_b)
    assert res_unauth.status_code == 404

    # 3. User A can access remediation
    res_auth = client.get(f"/api/v1/remediations/{rem_id}", headers=headers_a)
    assert res_auth.status_code == 200
    assert res_auth.json()["id"] == rem_id


def test_human_approval_gate_and_controlled_application(
    client: TestClient, db_session: Session, tmp_path: Path
):
    """Verify that patch application requires human approval and applies cleanly in isolated workspace."""
    user_id = f"rem_gate_{uuid.uuid4().hex[:8]}"
    headers = {"x-user-id": user_id}

    # Setup sandbox workspace
    ws_dir = tmp_path / "sandbox_repo"
    ws_dir.mkdir()
    target_rel = "app/demo_rag/routes.py"
    target_abs = ws_dir / "app" / "demo_rag" / "routes.py"
    target_abs.parent.mkdir(parents=True, exist_ok=True)
    orig_code = 'demo_state = {\n    "vulnerable_mode": True,\n}\n'
    target_abs.write_text(orig_code, encoding="utf-8")

    scan = ScanRepository.create_scan(
        db=db_session,
        target_identifier="http://testserver/api/v1/demo-rag/query",
        configuration={"preset": "quick_scan"},
        user_id=user_id,
        preset="quick_scan",
        status="COMPLETED",
    )
    finding = FindingRepository.create_finding(
        db=db_session,
        scan_id=scan.id,
        category="prompt_injection",
        severity="HIGH",
        title="System Prompt Extraction",
        description="Leaked system instructions",
        evidence={},
        affected_test_case="direct_02",
        target_component="app/demo_rag/routes.py",
    )

    # 1. Initiate remediation with custom workspace root
    init_res = client.post(
        f"/api/v1/remediations/findings/{finding.id}",
        json={"workspace_root": str(ws_dir)},
        headers=headers,
    )
    assert init_res.status_code == 200
    rem_id = init_res.json()["id"]
    patch_id = init_res.json()["latest_patch_id"]
    assert patch_id is not None

    # 2. Try to apply patch WITHOUT approval -> Must fail with 400
    unapproved_apply = client.post(
        f"/api/v1/remediations/patches/{patch_id}/apply",
        json={"workspace_root": str(ws_dir)},
        headers=headers,
    )
    assert unapproved_apply.status_code == 400
    assert "Human Operator" in unapproved_apply.json()["detail"] or "approved" in unapproved_apply.json()["detail"]

    # 3. Explicit Human Approval
    app_res = client.post(
        f"/api/v1/remediations/patches/{patch_id}/approve",
        json={"decision": "APPROVED", "reason": "Operator verified diff"},
        headers=headers,
    )
    assert app_res.status_code == 200
    assert app_res.json()["decision"] == "APPROVED"

    # 4. Apply Approved Patch
    apply_res = client.post(
        f"/api/v1/remediations/patches/{patch_id}/apply",
        json={"workspace_root": str(ws_dir)},
        headers=headers,
    )
    assert apply_res.status_code == 200
    assert apply_res.json()["status"] == "APPLIED"
    assert target_rel in apply_res.json()["applied_files"]

    # Verify file content changed on disk
    modified_code = target_abs.read_text(encoding="utf-8")
    assert '"vulnerable_mode": False' in modified_code

    # 5. Download Patch file
    dl_res = client.get(f"/api/v1/remediations/patches/{patch_id}/download", headers=headers)
    assert dl_res.status_code == 200
    assert "---" in dl_res.text and "+++" in dl_res.text

    # 6. Verify Remediation (tests + retest)
    verify_res = client.post(
        f"/api/v1/remediations/{rem_id}/verify",
        headers=headers,
    )
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    assert v_data["retest_status"] in ("FIXED", "NOT_FIXED", "PARTIALLY_FIXED")
    assert "test_summary" in v_data

    # 7. Rollback applied patch
    rollback_res = client.post(
        f"/api/v1/remediations/{rem_id}/rollback",
        json={"workspace_root": str(ws_dir)},
        headers=headers,
    )
    assert rollback_res.status_code == 200
    assert rollback_res.json()["status"] == "ROLLED_BACK"

    # Verify file content was restored
    restored_code = target_abs.read_text(encoding="utf-8")
    assert restored_code == orig_code


def test_remediation_project_history(client: TestClient, db_session: Session):
    """Verify remediation history listing for a project."""
    user_id = f"rem_hist_{uuid.uuid4().hex[:8]}"
    headers = {"x-user-id": user_id}

    proj = ProjectRepository.create_project(
        db=db_session,
        name="History Project",
        application_type="rag",
        environment="development",
        target_type="demo",
        owner_id=user_id,
    )
    scan = ScanRepository.create_scan(
        db=db_session,
        target_identifier="http://testserver/api/v1/demo-rag/query",
        configuration={"preset": "quick_scan"},
        project_id=proj.id,
        user_id=user_id,
        preset="quick_scan",
        status="COMPLETED",
    )
    finding = FindingRepository.create_finding(
        db=db_session,
        scan_id=scan.id,
        category="data_leakage",
        severity="HIGH",
        title="Canary Token Leak",
        description="Canary secret exposed",
        evidence={},
        affected_test_case="canary_01",
        target_component="app/demo_rag/routes.py",
    )

    client.post(f"/api/v1/remediations/findings/{finding.id}", headers=headers)

    # Fetch history
    hist_res = client.get(f"/api/v1/remediations/projects/{proj.id}/history", headers=headers)
    assert hist_res.status_code == 200
    h_data = hist_res.json()
    assert h_data["total"] >= 1
    assert h_data["items"][0]["finding_id"] == finding.id


def test_patch_rejection_prevents_file_modification(
    client: TestClient, db_session: Session, tmp_path: Path
):
    """Verify that rejected patches are never applied to workspace files."""
    user_id = f"rem_rej_{uuid.uuid4().hex[:8]}"
    headers = {"x-user-id": user_id}

    ws_dir = tmp_path / "reject_repo"
    ws_dir.mkdir()
    target_abs = ws_dir / "app" / "demo_rag" / "routes.py"
    target_abs.parent.mkdir(parents=True, exist_ok=True)
    orig_code = 'demo_state = {"vulnerable_mode": True}\n'
    target_abs.write_text(orig_code, encoding="utf-8")

    scan = ScanRepository.create_scan(
        db=db_session,
        target_identifier="http://testserver/api/v1/demo-rag/query",
        configuration={"preset": "quick_scan"},
        user_id=user_id,
        preset="quick_scan",
        status="COMPLETED",
    )
    finding = FindingRepository.create_finding(
        db=db_session,
        scan_id=scan.id,
        category="prompt_injection",
        severity="HIGH",
        title="Injection Bypass",
        description="Test finding",
        evidence={},
        affected_test_case="direct_03",
        target_component="app/demo_rag/routes.py",
    )

    init_res = client.post(
        f"/api/v1/remediations/findings/{finding.id}",
        json={"workspace_root": str(ws_dir)},
        headers=headers,
    )
    patch_id = init_res.json()["latest_patch_id"]

    # Explicit rejection
    rej_res = client.post(
        f"/api/v1/remediations/patches/{patch_id}/reject",
        json={"reason": "Contains undesirable behavioral changes"},
        headers=headers,
    )
    assert rej_res.status_code == 200
    assert rej_res.json()["decision"] == "REJECTED"

    # Attempt to apply rejected patch
    apply_res = client.post(
        f"/api/v1/remediations/patches/{patch_id}/apply",
        json={"workspace_root": str(ws_dir)},
        headers=headers,
    )
    assert apply_res.status_code == 400
    assert "approved" in apply_res.json()["detail"].lower()

    # Confirm file on disk was not modified
    assert target_abs.read_text(encoding="utf-8") == orig_code


def test_stale_patch_rejection_on_source_file_drift(
    client: TestClient, db_session: Session, tmp_path: Path
):
    """Verify that if source files change on disk after patch generation, patch application is rejected."""
    user_id = f"rem_drift_{uuid.uuid4().hex[:8]}"
    headers = {"x-user-id": user_id}

    ws_dir = tmp_path / "drift_repo"
    ws_dir.mkdir()
    target_abs = ws_dir / "app" / "demo_rag" / "routes.py"
    target_abs.parent.mkdir(parents=True, exist_ok=True)
    orig_code = 'demo_state = {"vulnerable_mode": True}\n'
    target_abs.write_text(orig_code, encoding="utf-8")

    scan = ScanRepository.create_scan(
        db=db_session,
        target_identifier="http://testserver/api/v1/demo-rag/query",
        configuration={"preset": "quick_scan"},
        user_id=user_id,
        preset="quick_scan",
        status="COMPLETED",
    )
    finding = FindingRepository.create_finding(
        db=db_session,
        scan_id=scan.id,
        category="prompt_injection",
        severity="HIGH",
        title="Drift Test Finding",
        description="Test finding",
        evidence={},
        affected_test_case="direct_04",
        target_component="app/demo_rag/routes.py",
    )

    init_res = client.post(
        f"/api/v1/remediations/findings/{finding.id}",
        json={"workspace_root": str(ws_dir)},
        headers=headers,
    )
    patch_id = init_res.json()["latest_patch_id"]

    # Approve patch
    client.post(f"/api/v1/remediations/patches/{patch_id}/approve", headers=headers)

    # Concurrently modify source file on disk before application (Drift)
    target_abs.write_text('demo_state = {"vulnerable_mode": True, "concurrent_edit": True}\n', encoding="utf-8")

    # Attempt to apply patch -> Must be rejected due to stale hash
    apply_res = client.post(
        f"/api/v1/remediations/patches/{patch_id}/apply",
        json={"workspace_root": str(ws_dir)},
        headers=headers,
    )
    assert apply_res.status_code == 400
    assert "validation failure" in apply_res.json()["detail"].lower()



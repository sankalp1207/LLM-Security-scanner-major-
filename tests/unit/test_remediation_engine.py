"""Unit tests for Phase 6 Automated Remediation Assistant workspace, patch validator, and library."""

from pathlib import Path
import pytest
from sqlalchemy.orm import Session

from app.database.connection import SessionLocal
from app.database.models import Finding, Project, Scan
from app.database.repository import (
    FindingRepository,
    ProjectRepository,
    RemediationRepository,
    ScanRepository,
)
from app.services.patch_validator import PatchValidator
from app.services.remediation_library import RemediationLibrary
from app.services.remediation_service import RemediationService
from app.services.remediation_workspace import ControlledWorkspace, WorkspaceSecurityError


def test_verification_outcome_requires_real_passing_tests_and_conclusive_retest():
    classify = RemediationService.classify_verification_outcome
    assert classify("RETEST_PASSED", 2, 0, 0) == "FIXED"
    assert classify("RETEST_FAILED", 2, 0, 0) == "NOT_FIXED"
    assert classify("RETEST_PASSED", 0, 0, 5) == "INCONCLUSIVE"
    assert classify("RETEST_INCONCLUSIVE", 2, 0, 0) == "INCONCLUSIVE"
    assert classify("RETEST_PASSED", 2, 1, 1) == "REGRESSION_DETECTED"


def test_controlled_workspace_path_safety_and_traversal_rejection(tmp_path: Path):
    """Verify ControlledWorkspace enforces boundary containment and blocks path traversal."""
    ws = tmp_path / "sandbox_workspace"
    ws.mkdir()

    # Valid safe relative path
    safe_path = ControlledWorkspace.resolve_safe_path("src/module.py", ws)
    assert safe_path == ws / "src" / "module.py"

    # Absolute path rejection
    with pytest.raises(WorkspaceSecurityError, match="Absolute filesystem paths"):
        ControlledWorkspace.resolve_safe_path("C:/Windows/System32/cmd.exe", ws)

    # Path traversal rejection
    with pytest.raises(WorkspaceSecurityError, match="Path traversal"):
        ControlledWorkspace.resolve_safe_path("../outside.py", ws)

    with pytest.raises(WorkspaceSecurityError, match="Path traversal"):
        ControlledWorkspace.resolve_safe_path("subdir/../../escape.py", ws)

    # Sensitive patterns rejection (.env, .git)
    with pytest.raises(WorkspaceSecurityError, match="forbidden"):
        ControlledWorkspace.resolve_safe_path(".env", ws)

    with pytest.raises(WorkspaceSecurityError, match="forbidden"):
        ControlledWorkspace.resolve_safe_path(".git/config", ws)

    with pytest.raises(WorkspaceSecurityError, match="forbidden"):
        ControlledWorkspace.resolve_safe_path("keys/id_rsa", ws)

    # Disallowed extension rejection (.exe, .sh)
    with pytest.raises(WorkspaceSecurityError, match="not permitted"):
        ControlledWorkspace.resolve_safe_path("script.exe", ws)


def test_controlled_workspace_atomic_patch_application_and_rollback(tmp_path: Path):
    """Verify atomic patch file writing, backup creation, and clean rollback."""
    ws = tmp_path / "app_workspace"
    ws.mkdir()

    # Create target file with original content
    target_file = ws / "guardrails.py"
    original_code = 'vulnerable_mode = True\nprint("running")\n'
    target_file.write_text(original_code, encoding="utf-8")

    patched_code = 'vulnerable_mode = False\nprint("running securely")\n'

    manifest = [
        {
            "path": "guardrails.py",
            "change_type": "modify",
            "patched_content": patched_code,
        }
    ]

    # 1. Apply patch
    applied_files, backup_manifest = ControlledWorkspace.apply_patch_files(manifest, ws)
    assert "guardrails.py" in applied_files
    assert backup_manifest["guardrails.py"] == original_code
    assert target_file.read_text(encoding="utf-8") == patched_code

    # 2. Rollback patch
    restored_files = ControlledWorkspace.rollback_patch_files(backup_manifest, workspace_root=ws)
    assert "guardrails.py" in restored_files
    assert target_file.read_text(encoding="utf-8") == original_code


def test_patch_validator_schema_and_stale_file_drift_detection(tmp_path: Path):
    """Verify PatchValidator rejects malformed schemas and detects stale source files."""
    ws = tmp_path / "drift_workspace"
    ws.mkdir()

    target_file = ws / "api.py"
    target_file.write_text('DEBUG = True\n', encoding="utf-8")
    original_hash = ControlledWorkspace.compute_sha256(target_file)

    # Valid patch
    manifest = [
        {
            "path": "api.py",
            "change_type": "modify",
            "reason": "Disable debug mode",
            "diff": "@@ -1 +1 @@\n-DEBUG = True\n+DEBUG = False",
            "patched_content": 'DEBUG = False\n',
        }
    ]
    report_valid = PatchValidator.validate_patch_safety_and_scope(
        patch_id="p1",
        files_manifest=manifest,
        source_hashes={"api.py": original_hash},
        workspace_root=ws,
    )
    assert report_valid.is_valid is True
    assert len(report_valid.errors) == 0

    # Modify file on disk to simulate concurrent developer edit (drift)
    target_file.write_text('DEBUG = True\n# Modified by other dev\n', encoding="utf-8")

    report_stale = PatchValidator.validate_patch_safety_and_scope(
        patch_id="p1",
        files_manifest=manifest,
        source_hashes={"api.py": original_hash},
        workspace_root=ws,
    )
    assert report_stale.is_valid is False
    assert any("Stale patch detected" in err for err in report_stale.errors)


def test_remediation_library_categories_and_root_cause():
    """Verify RemediationLibrary provides structured templates and root causes across vulnerability classes."""
    for cat in (
        "prompt_injection",
        "indirect_injection",
        "data_leakage",
        "rag_auth",
        "unsafe_tool",
    ):
        root_cause = RemediationLibrary.get_root_cause_analysis(category=cat, affected_component="llm_rag")
        assert len(root_cause) > 30
        assert "Root Cause" in root_cause


def test_remediation_repository_crud_lifecycle(db_session: Session):
    """Verify RemediationRepository persists remediations, patches, approvals, and executions."""
    user_id = "test_remed_repo_user"

    # Setup parent scan and finding
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
        title="Direct Injection Bypass",
        description="Prompt injection exploit",
        evidence={},
        affected_test_case="tc_01",
    )

    # 1. Create remediation
    rem = RemediationRepository.create_remediation(
        db=db_session,
        finding_id=finding.id,
        user_id=user_id,
        summary="Mitigate Direct Injection Bypass",
        root_cause_analysis="Missing boundary delimiters",
        affected_component="app/demo_rag/routes.py",
        status="ANALYZING",
    )
    assert rem.id is not None
    assert rem.status == "ANALYZING"

    # 2. Create patch
    patch = RemediationRepository.create_patch(
        db=db_session,
        remediation_id=rem.id,
        summary="Toggle vulnerable_mode to False",
        files_manifest=[{"path": "app/demo_rag/routes.py", "change_type": "modify"}],
        diff_content="--- a\n+++ b\n",
        source_hashes={"app/demo_rag/routes.py": "abc123hash"},
        validation_status="VALID",
    )
    assert patch.id is not None
    assert patch.patch_version == 1

    # 3. Create approval
    appr = RemediationRepository.create_approval(
        db=db_session,
        patch_id=patch.id,
        user_id=user_id,
        decision="APPROVED",
        reason="Looks safe to apply",
    )
    assert appr.id is not None
    assert appr.decision == "APPROVED"

    # 4. Create execution
    exec_rec = RemediationRepository.create_execution(
        db=db_session,
        remediation_id=rem.id,
        patch_id=patch.id,
        execution_status="APPLIED",
        backup_manifest={"app/demo_rag/routes.py": "orig_code"},
    )
    assert exec_rec.id is not None
    assert exec_rec.execution_status == "APPLIED"

    # 5. Update execution with retest
    updated_exec = RemediationRepository.update_execution(
        db=db_session,
        execution_id=exec_rec.id,
        test_summary={"tests_passed": 2},
        retest_status="FIXED",
    )
    assert updated_exec.retest_status == "FIXED"


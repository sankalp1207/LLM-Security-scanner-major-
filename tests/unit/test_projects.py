"""Unit tests for credential security, connection verification, SSRF defense, and project repositories."""

import uuid

import pytest
from app.database.connection import SessionLocal
from app.database.repository import (
    ProjectRepository,
    TargetConfigurationRepository,
    UserOnboardingRepository,
)
from app.services.connection_verifier import ConnectionVerifier
from app.services.crypto_service import CryptoService


def test_crypto_service_encryption_and_decryption():
    """Verify that credentials are encrypted to ciphertext and cleanly decrypted."""
    secret = "sk-proj-super-secret-key-12345"
    encrypted = CryptoService.encrypt_credential(secret)

    assert encrypted != ""
    assert encrypted != secret
    assert len(encrypted) > len(secret)

    decrypted = CryptoService.decrypt_credential(encrypted)
    assert decrypted == secret


def test_crypto_service_credential_masking():
    """Verify that credentials are never exposed in plaintext and are masked securely."""
    secret = "sk-proj-test-token-9988"
    masked = CryptoService.mask_credential(secret)

    assert "••••••••" in masked
    assert masked.startswith("sk-")
    assert masked.endswith("9988")
    assert secret not in masked

    # Empty credential masking
    assert CryptoService.mask_credential("") == ""
    assert CryptoService.mask_credential(None) == ""


def test_ssrf_destination_validation():
    """Verify SSRF defense blocks cloud metadata and loopbacks for external targets."""
    # Prohibited cloud metadata
    allowed, reason = ConnectionVerifier.validate_destination_ssrf(
        "http://169.254.169.254/latest/meta-data", allow_local=False
    )
    assert allowed is False
    assert "metadata" in reason.lower() or "ssrf" in reason.lower()

    # Loopback blocked when allow_local is False
    allowed_loop, reason_loop = ConnectionVerifier.validate_destination_ssrf(
        "http://127.0.0.1:8000/query", allow_local=False
    )
    assert allowed_loop is False
    assert "loopback" in reason_loop.lower()

    # Loopback permitted when allow_local is True (Local Demo / Local LLM)
    allowed_local, _ = ConnectionVerifier.validate_destination_ssrf(
        "http://127.0.0.1:8000/query", allow_local=True
    )
    assert allowed_local is True

    # Invalid scheme blocked
    allowed_ftp, reason_ftp = ConnectionVerifier.validate_destination_ssrf(
        "ftp://example.com/api", allow_local=False
    )
    assert allowed_ftp is False
    assert "scheme" in reason_ftp.lower()


def test_project_repository_lifecycle():
    """Verify project creation, duplicate name check, update, and deletion in repository."""
    db = SessionLocal()
    try:
        suffix = uuid.uuid4().hex[:8]
        p_name = f"Unit Test Repo Project {suffix}"
        owner = f"unit_test_user_{suffix}"

        # Create
        proj = ProjectRepository.create_project(
            db=db,
            name=p_name,
            owner_id=owner,
            description="Unit test project scope",
            application_type="chatbot",
            environment="testing",
            target_type="demo",
        )
        assert proj.id is not None
        assert proj.name == p_name

        # Duplicate check
        dup = ProjectRepository.get_project_by_name(db, name=p_name, owner_id=owner)
        assert dup is not None
        assert dup.id == proj.id

        # Update
        updated = ProjectRepository.update_project(
            db=db,
            project_id=proj.id,
            updates={"description": "Updated scope"},
            owner_id=owner,
        )
        assert updated.description == "Updated scope"

        # Upsert target config
        tc = TargetConfigurationRepository.upsert_configuration(
            db=db,
            project_id=proj.id,
            provider="demo",
            endpoint_url="http://127.0.0.1:8000/api/v1/demo-rag/query",
        )
        assert tc.project_id == proj.id

        # Delete
        deleted = ProjectRepository.delete_project(db=db, project_id=proj.id, owner_id=owner)
        assert deleted is True

        # Confirm gone
        assert ProjectRepository.get_project(db=db, project_id=proj.id) is None
    finally:
        db.close()


def test_user_onboarding_repository():
    """Verify onboarding status retrieval, completion, and reset."""
    db = SessionLocal()
    uid = f"onboarding_test_user_{uuid.uuid4().hex[:8]}"
    try:
        # Initially none
        initial = UserOnboardingRepository.get_status(db, uid)
        assert initial is None

        # Complete
        completed = UserOnboardingRepository.complete_onboarding(
            db=db, user_id=uid, selected_demo=True, active_project_id="demo-p-1"
        )
        assert completed.is_completed is True
        assert completed.selected_demo is True

        # Retrieve
        status = UserOnboardingRepository.get_status(db, uid)
        assert status is not None
        assert status.is_completed is True

        # Reset
        reset = UserOnboardingRepository.reset_onboarding(db, uid)
        assert reset.is_completed is False
        assert reset.completed_at is None
    finally:
        # Cleanup
        rec = UserOnboardingRepository.get_status(db, uid)
        if rec:
            db.delete(rec)
            db.commit()
        db.close()

"""Unit tests for dataset versioning, metadata tracking, provenance, and contamination prevention."""

import json
from pathlib import Path

import pytest

from app.database.connection import SessionLocal, init_db
from app.database.repository import TestCaseRepository, TestSuiteRepository
from app.ml.dataset import (
    TestCaseRecord,
    calculate_dataset_checksum,
    export_dataset_metadata,
    validate_jsonl_content,
)


def test_test_case_record_versioning_defaults():
    """Verify versioned test case record defaults and metadata synchronization."""
    record = TestCaseRecord(
        id="VER-001",
        category="prompt_injection",
        input="System prompt leak test",
        expected_behavior="blocked_or_safe",
        rationale="Instruction override probe",
    )

    assert record.version == "1.0.0"
    assert record.provenance == "internal_synthetic"
    assert record.license == "MIT"
    assert record.dataset_type == "evaluation"
    assert record.enabled is True
    assert record.retired is False
    assert record.objective == "Instruction override probe"  # Synced from rationale


def test_test_case_record_objective_sync():
    """Verify objective populates rationale when rationale is not passed."""
    record = TestCaseRecord(
        id="VER-002",
        category="jailbreak",
        input="Persona bypass",
        expected_behavior="blocked_or_safe",
        objective="Verify model refuses DAN roleplay",
    )
    assert record.rationale == "Verify model refuses DAN roleplay"


def test_dataset_contamination_prevention():
    """Verify that validate_jsonl_content detects and blocks evaluation data leaking into training."""
    raw_jsonl = (
        '{"id": "TR-001", "category": "prompt_injection", "input": "test 1", "expected_behavior": "safe", "dataset_type": "training"}\n'
        '{"id": "EV-001", "category": "prompt_injection", "input": "test 2", "expected_behavior": "safe", "dataset_type": "evaluation"}\n'
    )

    # When validating for 'training' partition, EV-001 must be flagged
    records, errors = validate_jsonl_content(raw_jsonl, expected_type="training")
    assert len(records) == 1
    assert records[0].id == "TR-001"
    assert len(errors) == 1
    assert "Type mismatch" in errors[0] or "contamination" in errors[0].lower()


def test_calculate_dataset_checksum(tmp_path):
    """Verify SHA-256 calculation on dataset files."""
    test_file = tmp_path / "test.jsonl"
    test_file.write_text('{"id": "T-1", "category": "benign", "input": "hi", "expected_behavior": "allow"}\n', encoding="utf-8")

    checksum1 = calculate_dataset_checksum(test_file)
    assert len(checksum1) == 64  # SHA-256 hex string

    # Modifying content must change checksum
    test_file.write_text('{"id": "T-1", "category": "benign", "input": "modified", "expected_behavior": "allow"}\n', encoding="utf-8")
    checksum2 = calculate_dataset_checksum(test_file)
    assert checksum1 != checksum2


def test_export_dataset_metadata():
    """Verify export_dataset_metadata produces metadata without leaking raw payloads."""
    records = [
        TestCaseRecord(
            id="EXP-001",
            category="data_leakage",
            input="SUPER_SECRET_PAYLOAD_CANARY_XYZ",
            expected_behavior="blocked_or_safe",
            objective="Extract secret canary token",
            tags=["sensitive", "canary"],
        )
    ]

    exported = export_dataset_metadata(records)
    assert len(exported) == 1
    assert exported[0]["id"] == "EXP-001"
    assert exported[0]["category"] == "data_leakage"
    assert "SUPER_SECRET_PAYLOAD_CANARY_XYZ" not in json.dumps(exported)


def test_test_case_repository_lifecycle():
    """Verify creating, updating, and retiring test cases in relational database."""
    init_db()
    db = SessionLocal()
    try:
        case_data = {
            "id": "LIFECYCLE-TEST-001",
            "version": "1.0.0",
            "category": "prompt_injection",
            "input": "Initial prompt payload",
            "expected_behavior": "blocked_or_safe",
            "rationale": "Initial lifecycle test",
            "tags": ["test", "lifecycle"],
            "dataset_type": "evaluation",
        }

        # 1. Create
        tc = TestCaseRepository.create_case(db, case_data)
        assert tc.id == "LIFECYCLE-TEST-001"
        assert tc.enabled is True
        assert tc.retired is False

        # 2. Update
        updated = TestCaseRepository.update_case(
            db,
            case_id="LIFECYCLE-TEST-001",
            update_data={"version": "1.1.0", "rationale": "Refined instruction override"},
        )
        assert updated is not None
        assert updated.version == "1.1.0"
        assert updated.test_rationale == "Refined instruction override"

        # 3. Retire
        retired = TestCaseRepository.retire_case(
            db,
            case_id="LIFECYCLE-TEST-001",
            reason="Superseded by updated benchmark suite",
        )
        assert retired is not None
        assert retired.retired is True
        assert retired.enabled is False
        assert retired.retirement_reason == "Superseded by updated benchmark suite"

        # Verify get_all excludes retired cases by default
        active_cases = TestCaseRepository.get_all(db, include_retired=False)
        assert not any(c.id == "LIFECYCLE-TEST-001" for c in active_cases)

        # But includes when include_retired=True
        all_cases = TestCaseRepository.get_all(db, include_retired=True)
        assert any(c.id == "LIFECYCLE-TEST-001" for c in all_cases)
    finally:
        # Cleanup
        try:
            db.rollback()
            to_delete = TestCaseRepository.get_by_id(db, "LIFECYCLE-TEST-001")
            if to_delete:
                db.delete(to_delete)
                db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()

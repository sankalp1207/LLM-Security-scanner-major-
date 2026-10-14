"""Unit tests for dataset parsing, validation, statistics, and stratified splitting."""

import json
from pathlib import Path

import pytest

from app.ml.dataset import (
    TestCaseRecord,
    get_dataset_statistics,
    load_dataset,
    split_dataset,
)


def test_load_real_synthetic_dataset():
    """Verify loading the actual generated synthetic security test suite."""
    dataset_path = Path("datasets/security_tests.jsonl")
    assert dataset_path.exists(), "Dataset file must exist"

    records = load_dataset(dataset_path)
    assert len(records) >= 100, f"Expected at least 100 records, got {len(records)}"

    categories = {r.category for r in records}
    expected_categories = {
        "prompt_injection",
        "indirect_prompt_injection",
        "jailbreak",
        "data_leakage",
        "benign",
    }
    assert expected_categories.issubset(categories)


def test_dataset_statistics():
    """Verify statistics calculation on records."""
    records = [
        TestCaseRecord(
            id="T1", category="prompt_injection", input="Short test", expected_behavior="block"
        ),
        TestCaseRecord(
            id="T2",
            category="prompt_injection",
            input="A much longer test input string",
            expected_behavior="block",
        ),
        TestCaseRecord(
            id="T3", category="benign", input="Normal query", expected_behavior="allow"
        ),
    ]

    stats = get_dataset_statistics(records)
    assert stats["total_records"] == 3
    assert stats["category_counts"]["prompt_injection"] == 2
    assert stats["category_counts"]["benign"] == 1
    assert stats["min_text_length"] == len("Short test")
    assert stats["max_text_length"] == len("A much longer test input string")


def test_duplicate_id_detection(tmp_path):
    """Verify ValueError is raised if duplicate IDs exist."""
    bad_file = tmp_path / "dup.jsonl"
    r1 = {
        "id": "DUP-1",
        "category": "benign",
        "input": "text1",
        "expected_behavior": "allow",
    }
    r2 = {
        "id": "DUP-1",
        "category": "jailbreak",
        "input": "text2",
        "expected_behavior": "block",
    }
    with open(bad_file, "w") as f:
        f.write(json.dumps(r1) + "\n" + json.dumps(r2) + "\n")

    with pytest.raises(ValueError, match="Duplicate test case ID"):
        load_dataset(bad_file)


def test_malformed_record_detection(tmp_path):
    """Verify ValueError is raised on invalid schema or invalid JSON."""
    bad_file = tmp_path / "bad.jsonl"
    with open(bad_file, "w") as f:
        f.write("{invalid json}\n")

    with pytest.raises(ValueError, match="Malformed dataset record"):
        load_dataset(bad_file)


def test_stratified_split():
    """Verify stratified split preserves proportional representation across splits."""
    dataset_path = Path("datasets/security_tests.jsonl")
    records = load_dataset(dataset_path)

    train_set, val_set, test_set = split_dataset(
        records, test_size=0.2, val_size=0.1, random_state=42
    )

    assert len(train_set) + len(val_set) + len(test_set) == len(records)
    assert len(test_set) == int(len(records) * 0.2)

    # Verify all categories exist in train and test sets
    train_cats = {r.category for r in train_set}
    test_cats = {r.category for r in test_set}
    assert len(train_cats) == 5
    assert len(test_cats) == 5

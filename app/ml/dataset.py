"""Dataset parsing, validation, statistical analysis, versioning, and stratified splitting."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field, ValidationError, model_validator
from sklearn.model_selection import train_test_split


class TestCaseRecord(BaseModel):
    """Schema validating individual versioned security test records."""

    id: str = Field(..., min_length=2, max_length=64, description="Stable test identifier")
    version: str = Field(default="1.0.0", description="Semantic test case version")
    category: str = Field(..., min_length=2, max_length=64, description="Threat category")
    input: str = Field(..., min_length=1, description="Payload or prompt text")
    expected_behavior: str = Field(..., min_length=1, description="Required defensive behavior")
    expected_outcome: str = Field(default="", description="Specific expected result status")
    rationale: str = Field(default="", description="Security rationale or objective")
    objective: str = Field(default="", description="Formal test objective")
    tags: List[str] = Field(default_factory=list, description="Categorization tags")
    provenance: str = Field(default="internal_synthetic", description="Origin or author of test case")
    license: str = Field(default="MIT", description="Dataset licensing terms")
    enabled: bool = Field(default=True, description="Whether test case is active")
    retired: bool = Field(default=False, description="Whether test case is retired/deprecated")
    retirement_reason: Optional[str] = Field(default=None, description="Reason for retirement")
    dataset_type: str = Field(
        default="evaluation",
        description="Dataset partition: 'training', 'evaluation', or 'benchmark'",
    )
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Custom metadata attributes")

    @model_validator(mode="after")
    def sync_objective_and_rationale(self) -> "TestCaseRecord":
        """Ensure objective and rationale remain synchronized for backward compatibility."""
        if not self.objective and self.rationale:
            self.objective = self.rationale
        elif not self.rationale and self.objective:
            self.rationale = self.objective
        return self


class TestSuiteMetadata(BaseModel):
    """Metadata describing a versioned test suite package."""

    suite_id: str = Field(..., description="Unique suite identifier")
    version: str = Field(..., description="Semantic version of suite")
    dataset_type: str = Field(..., description="'training' or 'evaluation'")
    description: str = Field(default="", description="Suite description and scope")
    license: str = Field(default="MIT", description="License identifier")
    provenance: str = Field(default="internal_benchmark", description="Origin/source tracking")
    record_count: int = Field(default=0, ge=0)
    checksum_sha256: str = Field(default="", description="SHA-256 hash of dataset content")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def calculate_dataset_checksum(file_path: str | Path) -> str:
    """Calculate the SHA-256 hash of a dataset file for integrity verification."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Dataset file not found: {path}")

    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def validate_jsonl_content(
    content: str,
    expected_type: Optional[str] = None,
    disallow_types: Optional[List[str]] = None,
) -> Tuple[List[TestCaseRecord], List[str]]:
    """
    Validate raw JSONL text content line-by-line.
    Returns (valid_records, validation_errors).
    Enforces no duplicate IDs and prevents contamination between dataset types.
    """
    records: List[TestCaseRecord] = []
    errors: List[str] = []
    seen_ids = set()

    for line_num, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        try:
            data = json.loads(stripped)
            record = TestCaseRecord(**data)
        except json.JSONDecodeError as e:
            errors.append(f"Line {line_num}: Malformed dataset record - invalid JSON: {e}")
            continue
        except ValidationError as e:
            field_errors = "; ".join([f"{err['loc']}: {err['msg']}" for err in e.errors()])
            errors.append(f"Line {line_num}: Malformed dataset record - schema error: {field_errors}")
            continue

        if record.id in seen_ids:
            errors.append(f"Line {line_num}: Duplicate test case ID '{record.id}'")
            continue
        seen_ids.add(record.id)

        # Contamination check: ensure training and evaluation data are never silently mixed
        if expected_type and record.dataset_type != expected_type:
            errors.append(
                f"Line {line_num}: Type mismatch for test case '{record.id}'. "
                f"Expected dataset_type='{expected_type}', found '{record.dataset_type}'."
            )
            continue

        if disallow_types and record.dataset_type in disallow_types:
            errors.append(
                f"Line {line_num}: Data contamination risk for test case '{record.id}'. "
                f"Type '{record.dataset_type}' is prohibited in this target partition."
            )
            continue

        records.append(record)

    return records, errors


def load_dataset(file_path: str | Path, enabled_only: bool = False) -> List[TestCaseRecord]:
    """Load and validate records from a JSONL file."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Dataset file not found at: {path}")

    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    records, errors = validate_jsonl_content(content)
    if errors:
        raise ValueError(f"Dataset errors in {path.name}:\n" + "\n".join(errors[:10]))

    if enabled_only:
        records = [r for r in records if r.enabled and not r.retired]

    return records


def export_dataset_metadata(records: List[TestCaseRecord]) -> List[Dict[str, Any]]:
    """Export permitted metadata for a list of test cases without exposing raw payloads."""
    return [
        {
            "id": r.id,
            "version": r.version,
            "category": r.category,
            "objective": r.objective,
            "expected_behavior": r.expected_behavior,
            "tags": r.tags,
            "provenance": r.provenance,
            "license": r.license,
            "enabled": r.enabled,
            "retired": r.retired,
            "dataset_type": r.dataset_type,
            "has_metadata": bool(r.metadata),
        }
        for r in records
    ]


def get_dataset_statistics(records: List[TestCaseRecord]) -> Dict[str, Any]:
    """Calculate class distributions, text length metrics, and tag distributions across records."""
    total = len(records)
    if total == 0:
        return {"total_records": 0, "category_counts": {}, "avg_text_length": 0.0}

    categories: Dict[str, int] = {}
    tags_count: Dict[str, int] = {}
    dataset_types: Dict[str, int] = {}
    total_len = 0
    min_len = float("inf")
    max_len = 0
    retired_count = 0

    for r in records:
        categories[r.category] = categories.get(r.category, 0) + 1
        dataset_types[r.dataset_type] = dataset_types.get(r.dataset_type, 0) + 1
        for t in r.tags:
            tags_count[t] = tags_count.get(t, 0) + 1
        if r.retired:
            retired_count += 1
        text_len = len(r.input)
        total_len += text_len
        min_len = min(min_len, text_len)
        max_len = max(max_len, text_len)

    category_percentages = {cat: round((count / total) * 100, 2) for cat, count in categories.items()}

    return {
        "total_records": total,
        "retired_records": retired_count,
        "active_records": total - retired_count,
        "category_counts": categories,
        "category_percentages": category_percentages,
        "dataset_types": dataset_types,
        "tag_distribution": tags_count,
        "min_text_length": min_len if min_len != float("inf") else 0,
        "max_text_length": max_len,
        "avg_text_length": round(total_len / total, 2),
    }


def split_dataset(
    records: List[TestCaseRecord],
    test_size: float = 0.2,
    val_size: float = 0.1,
    random_state: int = 42,
) -> Tuple[List[TestCaseRecord], List[TestCaseRecord], Optional[List[TestCaseRecord]]]:
    """Stratified train/validation/test split for dataset records."""
    if len(records) < 10:
        raise ValueError("Dataset has too few records for meaningful stratified splitting.")

    labels = [r.category for r in records]

    # First split off test set
    train_val, test_records, _, _ = train_test_split(
        records,
        labels,
        test_size=test_size,
        random_state=random_state,
        stratify=labels,
    )

    if val_size <= 0.0:
        return train_val, test_records, None

    # Calculate proportional validation size relative to train_val
    relative_val_size = val_size / (1.0 - test_size)
    train_val_labels = [r.category for r in train_val]

    train_records, val_records, _, _ = train_test_split(
        train_val,
        train_val_labels,
        test_size=relative_val_size,
        random_state=random_state,
        stratify=train_val_labels,
    )

    return train_records, val_records, test_records

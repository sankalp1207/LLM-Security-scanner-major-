"""Dataset parsing, validation, statistical analysis, and stratified splitting."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field, ValidationError
from sklearn.model_selection import train_test_split


class TestCaseRecord(BaseModel):
    """Schema validating individual security test records."""

    id: str = Field(..., min_length=2, max_length=64)
    category: str = Field(..., min_length=2, max_length=64)
    input: str = Field(..., min_length=1)
    expected_behavior: str = Field(..., min_length=1)
    expected_outcome: str = Field(default="")
    rationale: str = Field(default="")
    enabled: bool = Field(default=True)
    metadata: Dict[str, Any] = Field(default_factory=dict)


def load_dataset(file_path: str | Path, enabled_only: bool = False) -> List[TestCaseRecord]:
    """Load and validate records from a JSONL file."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Dataset file not found at: {path}")

    records: List[TestCaseRecord] = []
    seen_ids = set()

    with open(path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            try:
                data = json.loads(stripped)
                record = TestCaseRecord(**data)
            except (json.JSONDecodeError, ValidationError) as e:
                raise ValueError(f"Malformed dataset record at {path.name}:{line_num}: {e}") from e

            if record.id in seen_ids:
                raise ValueError(f"Duplicate test case ID '{record.id}' at {path.name}:{line_num}")
            seen_ids.add(record.id)

            if not enabled_only or record.enabled:
                records.append(record)

    return records


def get_dataset_statistics(records: List[TestCaseRecord]) -> Dict[str, Any]:
    """Calculate class distributions and text length metrics across dataset records."""
    total = len(records)
    if total == 0:
        return {"total": 0, "categories": {}, "avg_text_length": 0.0}

    categories: Dict[str, int] = {}
    total_len = 0
    min_len = float("inf")
    max_len = 0

    for r in records:
        categories[r.category] = categories.get(r.category, 0) + 1
        text_len = len(r.input)
        total_len += text_len
        min_len = min(min_len, text_len)
        max_len = max(max_len, text_len)

    category_percentages = {cat: round((count / total) * 100, 2) for cat, count in categories.items()}

    return {
        "total_records": total,
        "category_counts": categories,
        "category_percentages": category_percentages,
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

"""Model evaluation and metrics persistence."""

from pathlib import Path
from typing import Any, Dict

import joblib
from sqlalchemy.orm import Session

from app.database.repository import EvaluationRepository
from app.ml.dataset import load_dataset, split_dataset
from app.ml.train import evaluate_split


def evaluate_existing_model(
    model_path: str | Path = "models/baseline_threat_classifier.joblib",
    dataset_path: str | Path = "datasets/security_tests.jsonl",
    threshold: float = 0.55,
) -> Dict[str, Any]:
    """Evaluate an existing trained model artifact on test split."""
    m_path = Path(model_path)
    if not m_path.is_file():
        raise FileNotFoundError(f"Model file not found at {m_path}")

    pipeline = joblib.load(m_path)
    records = load_dataset(dataset_path)
    _, _, test_records = split_dataset(records, test_size=0.2, val_size=0.1, random_state=42)

    return evaluate_split(pipeline, test_records or [], threshold=threshold)


def record_evaluation_to_db(
    db: Session,
    metrics: Dict[str, Any],
    dataset_version: str = "v1.0-synthetic",
    model_version: str = "tfidf-logreg-v1",
) -> Any:
    """Record evaluation results into database."""
    eval_payload = {
        "dataset_version": dataset_version,
        "model_version": model_version,
        "precision": metrics["precision"],
        "recall": metrics["recall"],
        "f1_score": metrics["f1_score"],
        "false_positive_rate": metrics["false_positive_rate"],
        "false_negative_rate": metrics["false_negative_rate"],
        "confusion_matrix": metrics["confusion_matrix"],
        "per_class_metrics": metrics["per_class_metrics"],
        "configuration": {"threshold": metrics["threshold_used"]},
    }
    return EvaluationRepository.record_evaluation(db, eval_payload)

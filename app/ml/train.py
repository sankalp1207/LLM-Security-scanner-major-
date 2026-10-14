"""Training pipeline for baseline TF-IDF + Logistic Regression threat classifier."""

import os
from pathlib import Path
from typing import Any, Dict, Tuple

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from sklearn.pipeline import Pipeline

from app.ml.dataset import TestCaseRecord, load_dataset, split_dataset


def build_pipeline() -> Pipeline:
    """Construct Scikit-learn text classification pipeline."""
    return Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                ngram_range=(1, 2),
                max_features=2500,
                sublinear_tf=True,
                token_pattern=r"(?u)\b\w+\b|[<>/=\[\]_-]+",
            ),
        ),
        (
            "clf",
            LogisticRegression(
                C=1.5,
                class_weight="balanced",
                random_state=42,
                max_iter=1000,
            ),
        ),
    ])


def evaluate_split(
    pipeline: Pipeline,
    records: list[TestCaseRecord],
    threshold: float = 0.5,
) -> Dict[str, Any]:
    """Evaluate pipeline predictions against ground truth labels."""
    texts = [r.input for r in records]
    # Binary ground truth: 1 if adversarial/suspicious, 0 if benign
    y_true = np.array([0 if r.category == "benign" else 1 for r in records])

    # Predict probabilities for class 1 (suspicious)
    probs = pipeline.predict_proba(texts)[:, 1]
    y_pred = (probs >= threshold).astype(int)

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="binary", zero_division=0
    )

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    # cm layout: [[TN, FP], [FN, TP]]
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])

    fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0
    fnr = round(fn / (fn + tp), 4) if (fn + tp) > 0 else 0.0

    # Per-category breakdown
    category_results: Dict[str, Dict[str, Any]] = {}
    for r, pred, prob in zip(records, y_pred, probs):
        cat = r.category
        if cat not in category_results:
            category_results[cat] = {"total": 0, "detected_threat": 0}
        category_results[cat]["total"] += 1
        if pred == 1:
            category_results[cat]["detected_threat"] += 1

    return {
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1_score": round(float(f1), 4),
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "per_class_metrics": category_results,
        "threshold_used": threshold,
    }


def train_and_save_model(
    dataset_path: str | Path = "datasets/security_tests.jsonl",
    output_dir: str | Path = "models",
    model_filename: str = "baseline_threat_classifier.joblib",
) -> Tuple[Pipeline, Dict[str, Any]]:
    """Train pipeline, evaluate on held-out split, and serialize artifact."""
    records = load_dataset(dataset_path)
    train_records, val_records, test_records = split_dataset(
        records, test_size=0.2, val_size=0.1, random_state=42
    )

    X_train = [r.input for r in train_records]
    y_train = [0 if r.category == "benign" else 1 for r in train_records]

    pipeline = build_pipeline()
    pipeline.fit(X_train, y_train)

    # Evaluate on held-out test split
    metrics = evaluate_split(pipeline, test_records or [], threshold=0.55)

    # Serialize pipeline
    os.makedirs(output_dir, exist_ok=True)
    out_path = Path(output_dir) / model_filename
    joblib.dump(pipeline, out_path)

    return pipeline, metrics

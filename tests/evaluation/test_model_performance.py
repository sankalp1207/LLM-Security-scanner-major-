"""Evaluation tests verifying baseline classifier performance on held-out security data."""

from app.ml.evaluate import evaluate_existing_model


def test_baseline_classifier_meets_performance_criteria():
    """Verify that the baseline threat classifier meets acceptable precision and recall standards."""
    metrics = evaluate_existing_model(
        model_path="models/baseline_threat_classifier.joblib",
        dataset_path="datasets/security_tests.jsonl",
        threshold=0.55,
    )

    # Sanity checks on real evaluation
    assert metrics["precision"] >= 0.80, f"Expected precision >= 0.80, got {metrics['precision']}"
    assert metrics["recall"] >= 0.80, f"Expected recall >= 0.80, got {metrics['recall']}"
    assert metrics["f1_score"] >= 0.80, f"Expected f1 >= 0.80, got {metrics['f1_score']}"

    # Verify per-class detection was tracked
    assert "prompt_injection" in metrics["per_class_metrics"]
    assert "benign" in metrics["per_class_metrics"]

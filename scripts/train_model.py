"""CLI script to train, evaluate, and save baseline threat classifier."""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.database.connection import SessionLocal, init_db
from app.ml.evaluate import record_evaluation_to_db
from app.ml.train import train_and_save_model

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("train_model")


def main() -> None:
    """Train baseline threat model and persist metrics."""
    logger.info("Initializing database...")
    init_db()

    logger.info("Starting model training on synthetic security test suite...")
    _, metrics = train_and_save_model(
        dataset_path="datasets/security_tests.jsonl",
        output_dir="models",
        model_filename="baseline_threat_classifier.joblib",
    )

    logger.info("=== HELD-OUT TEST EVALUATION METRICS ===")
    logger.info(f"Precision:           {metrics['precision']:.4f}")
    logger.info(f"Recall:              {metrics['recall']:.4f}")
    logger.info(f"F1-Score:            {metrics['f1_score']:.4f}")
    logger.info(f"False Positive Rate: {metrics['false_positive_rate']:.4f}")
    logger.info(f"False Negative Rate: {metrics['false_negative_rate']:.4f}")
    logger.info(f"Confusion Matrix:    {metrics['confusion_matrix']}")
    logger.info("=========================================")

    # Persist evaluation record
    db = SessionLocal()
    try:
        record = record_evaluation_to_db(db, metrics)
        logger.info(f"Recorded evaluation to database with ID: {record.id}")
    finally:
        db.close()

    logger.info("Model training and evaluation successfully completed.")


if __name__ == "__main__":
    main()

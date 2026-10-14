import logging
import sys
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.database.connection import SessionLocal, init_db
from app.database.repository import TestCaseRepository
from app.ml.dataset import load_dataset

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("seed_database")


def main() -> None:
    """Initialize database tables and seed test cases from dataset."""
    logger.info("Initializing relational database schema...")
    init_db()
    logger.info("Database schema initialized successfully.")

    dataset_file = Path(__file__).resolve().parent.parent / "datasets" / "security_tests.jsonl"
    if dataset_file.exists():
        logger.info(f"Loading test cases from {dataset_file}...")
        records = load_dataset(dataset_file)
        dicts = [r.model_dump() for r in records]
        db = SessionLocal()
        try:
            inserted = TestCaseRepository.bulk_upsert(db, dicts)
            logger.info(f"Successfully seeded {inserted} security test cases into database.")
        finally:
            db.close()
    else:
        logger.warning(f"Dataset file not found at {dataset_file}, skipping test case seeding.")


if __name__ == "__main__":
    main()

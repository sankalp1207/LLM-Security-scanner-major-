import logging
import sys
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.database.connection import init_db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("seed_database")


def main() -> None:
    """Initialize database tables."""
    logger.info("Initializing relational database schema...")
    init_db()
    logger.info("Database schema initialized successfully.")


if __name__ == "__main__":
    main()

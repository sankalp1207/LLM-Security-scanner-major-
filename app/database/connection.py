"""Database connection and session management with schema auto-migration."""

from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from app.config import get_settings

settings = get_settings()

db_url = settings.DATABASE_URL
connect_args = {}

if db_url.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    db_url,
    connect_args=connect_args,
    pool_pre_ping=True,
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """Provide a transactional database session scope."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Initialize database tables according to SQLAlchemy metadata and apply auto-migrations."""
    import app.database.models  # noqa: F401 - ensure models are registered on Base metadata
    Base.metadata.create_all(bind=engine)

    # Auto-migration for SQLite schema evolution
    if engine.url.drivername.startswith("sqlite"):
        with engine.connect() as conn:
            try:
                result = conn.exec_driver_sql("PRAGMA table_info(security_test_cases)")
                cols = {row[1] for row in result.fetchall()}
                if cols:
                    new_cols = {
                        "version": "VARCHAR(32) DEFAULT '1.0.0'",
                        "objective": "TEXT DEFAULT ''",
                        "tags": "JSON DEFAULT '[]'",
                        "provenance": "VARCHAR(128) DEFAULT 'internal_synthetic'",
                        "license": "VARCHAR(64) DEFAULT 'MIT'",
                        "retired": "BOOLEAN DEFAULT 0",
                        "retirement_reason": "TEXT",
                        "dataset_type": "VARCHAR(32) DEFAULT 'evaluation'",
                        "suite_version": "VARCHAR(32) DEFAULT 'v1.0.0'",
                        "created_at": "DATETIME",
                        "updated_at": "DATETIME",
                    }
                    for col_name, col_type in new_cols.items():
                        if col_name not in cols:
                            conn.exec_driver_sql(f"ALTER TABLE security_test_cases ADD COLUMN {col_name} {col_type}")

                # Ensure Phase 2 and Phase 3 columns on scans table
                scan_res = conn.exec_driver_sql("PRAGMA table_info(scans)")
                scan_cols = {row[1] for row in scan_res.fetchall()}
                if scan_cols:
                    scan_new_cols = {
                        "project_id": "VARCHAR(64)",
                        "user_id": "VARCHAR(64) DEFAULT 'default_user'",
                        "preset": "VARCHAR(32) DEFAULT 'quick_scan'",
                        "target_configuration_id": "VARCHAR(64)",
                        "configuration_snapshot": "JSON DEFAULT '{}'",
                        "total_tests": "INTEGER DEFAULT 0",
                        "completed_tests": "INTEGER DEFAULT 0",
                        "passed_tests": "INTEGER DEFAULT 0",
                        "failed_tests": "INTEGER DEFAULT 0",
                        "inconclusive_tests": "INTEGER DEFAULT 0",
                        "skipped_tests": "INTEGER DEFAULT 0",
                        "execution_errors": "INTEGER DEFAULT 0",
                        "cancellation_reason": "TEXT",
                        "failure_reason": "TEXT",
                    }
                    for col_name, col_type in scan_new_cols.items():
                        if col_name not in scan_cols:
                            conn.exec_driver_sql(f"ALTER TABLE scans ADD COLUMN {col_name} {col_type}")

                conn.commit()
            except Exception:
                pass

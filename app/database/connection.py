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
                    conn.commit()
            except Exception:
                pass

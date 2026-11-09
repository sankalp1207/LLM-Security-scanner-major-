"""Application configuration using Pydantic Settings."""

from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration settings for LLM Security Scanner."""

    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"

    # API Info
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "LLM Security Scanner"
    VERSION: str = "1.0.0"
    HOST: str = "127.0.0.1"
    PORT: int = 8000

    # Persistence
    DATABASE_URL: str = "sqlite:///./llm_security_scanner.db"
    ENCRYPTION_KEY: str = ""

    # Scanner Guardrails & Limits
    SCANNER_REQUEST_TIMEOUT_SECONDS: float = 10.0
    SCANNER_MAX_CONCURRENT_TESTS: int = 5
    SCANNER_MAX_PAYLOAD_SIZE_BYTES: int = 32768
    ALLOWED_HOSTS: List[str] = ["127.0.0.1", "localhost"]

    # Demo RAG Settings
    DEMO_RAG_HOST: str = "127.0.0.1"
    DEMO_RAG_PORT: int = 8000
    DEMO_RAG_VULNERABLE_MODE: bool = True

    # ML Classifier Settings
    MODEL_DIR: str = "models"
    MODEL_FILENAME: str = "baseline_threat_classifier.joblib"
    DETECTION_THRESHOLD: float = 0.65

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings instance."""
    return Settings()

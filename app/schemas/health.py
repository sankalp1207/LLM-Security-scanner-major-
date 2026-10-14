"""Health check schemas."""

from typing import Dict

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Health check response schema."""

    status: str = Field(..., example="healthy")
    environment: str = Field(..., example="development")
    version: str = Field(..., example="1.0.0")
    timestamp: str = Field(..., example="2026-10-14T08:00:00Z")
    components: Dict[str, str] = Field(
        default_factory=dict,
        example={"database": "operational", "ml_classifier": "not_loaded"},
    )

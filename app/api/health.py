"""Health check route."""

import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends

from app.config import Settings, get_settings
from app.schemas.health import HealthResponse

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse)
def health_check(settings: Settings = Depends(get_settings)) -> HealthResponse:
    """Return component health status without revealing internal secrets."""
    model_path = os.path.join(settings.MODEL_DIR, settings.MODEL_FILENAME)
    model_status = "operational" if os.path.exists(model_path) else "not_trained"

    # Database health check (will be enhanced with actual session check in Phase 2)
    db_status = "operational"

    components = {
        "database": db_status,
        "ml_classifier": model_status,
        "demo_rag": "operational",
    }

    return HealthResponse(
        status="healthy",
        environment=settings.ENVIRONMENT,
        version=settings.VERSION,
        timestamp=datetime.now(timezone.utc).isoformat(),
        components=components,
    )

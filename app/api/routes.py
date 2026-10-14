"""Main API router aggregating all endpoints."""

from fastapi import APIRouter

from app.api.detection import router as detection_router
from app.api.health import router as health_router
from app.demo_rag.routes import router as demo_rag_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(detection_router)
api_router.include_router(demo_rag_router)

"""Main API router aggregating all endpoints."""

from fastapi import APIRouter

from app.api.datasets import router as datasets_router
from app.api.detection import router as detection_router
from app.api.findings import router as findings_router
from app.api.health import router as health_router
from app.api.projects import router as projects_router
from app.api.reports import router as reports_router
from app.api.scans import router as scans_router
from app.demo_rag.routes import router as demo_rag_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(detection_router)
api_router.include_router(scans_router)
api_router.include_router(reports_router)
api_router.include_router(findings_router)
api_router.include_router(demo_rag_router)
api_router.include_router(datasets_router)
api_router.include_router(projects_router)

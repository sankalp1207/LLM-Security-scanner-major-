"""FastAPI Application entrypoint for LLM Security Scanner."""

import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.auth import resolve_user_identity
from app.api.health import router as health_router
from app.api.routes import api_router
from app.config import get_settings

settings = get_settings()

logging.basicConfig(
    level=settings.LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("llm_security_scanner")


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    application = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        description=(
            "An Automated Vulnerability Detection and Security Testing Platform "
            "for Large Language Model Applications."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # CORS configuration for dashboard integration
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @application.middleware("http")
    async def require_api_identity(request: Request, call_next):
        """Require a signed identity for every production API route except health checks."""
        if (
            settings.ENVIRONMENT.strip().lower() == "production"
            and request.url.path.startswith(settings.API_V1_STR)
            and request.url.path not in (f"{settings.API_V1_STR}/health",)
        ):
            try:
                request.state.user_id = resolve_user_identity(
                    request.headers.get("authorization"),
                    request.headers.get("x-user-id"),
                    settings,
                )
            except HTTPException as exc:
                return JSONResponse(
                    status_code=exc.status_code,
                    content={"detail": exc.detail},
                    headers=exc.headers,
                )
        return await call_next(request)

    # Root endpoint
    @application.get("/", tags=["General"])
    def root() -> dict:
        """Root endpoint returning platform information and docs location."""
        return {
            "name": settings.PROJECT_NAME,
            "version": settings.VERSION,
            "docs": "/docs",
            "health": "/health",
            "status": "operational",
        }

    # Top-level health check endpoint per spec (GET /health)
    application.include_router(health_router)

    # API v1 routes
    application.include_router(api_router, prefix=settings.API_V1_STR)

    # Global safe exception handler: avoid stack trace leakage
    @application.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.error(f"Unhandled error on {request.method} {request.url.path}: {exc}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "error": "InternalServerError",
                "message": "An unexpected error occurred. Please contact the administrator.",
            },
        )

    return application


app = create_app()

"""
RESILIX — Secure Predictive Infrastructure Resilience System
Seva First Innovation Challenge 2026 | Surakshit Bharat — Security & Resilience
Tagline: Detect early. Operate offline. Recover securely.

Main FastAPI Application Entrypoint (`app.main:app`)
"""
import logging
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import api_router
from app.config import settings
from app.database import db_session, utc_now_iso
from app.models.schema import init_db_schema
from app.services.seed_service import seed_initial_data
from app.simulator.engine import simulator_engine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("resilix")

app = FastAPI(
    title="RESILIX API — Secure Predictive Infrastructure Resilience System",
    description=(
        "Seva First Innovation Challenge 2026 | Surakshit Bharat — Security & Resilience. "
        "Local-first equipment telemetry monitoring, explainable anomaly detection, "
        "sensor-data integrity validation, SHA-256 event hash chain, and store-and-forward offline synchronization."
    ),
    version=settings.app_version,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-CSRF-Token"],
)


@app.middleware("http")
async def request_size_and_security_headers_middleware(request: Request, call_next: Any) -> Any:
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > settings.max_request_body_bytes:
                return JSONResponse(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    content={"detail": "Request payload exceeds maximum permitted size."},
                )
        except ValueError:
            pass

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    # Return clean validation error messages without leaking internal stack traces
    errors = []
    for err in exc.errors():
        loc = " -> ".join(str(x) for x in err.get("loc", []))
        msg = err.get("msg", "Invalid value")
        errors.append(f"{loc}: {msg}")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": "; ".join(errors) if errors else "Request validation failed.",
            "validation_errors": exc.errors(),
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error("Unhandled exception on %s: %s", request.url.path, str(exc))
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "An internal server error occurred. Please check server logs.",
            "timestamp": utc_now_iso(),
        },
    )


@app.on_event("startup")
def on_startup() -> None:
    init_db_schema()
    with db_session() as db:
        seed_initial_data(db, force_reset=False)
    logger.info("RESILIX database initialized and seeded at %s", settings.database_path)


@app.on_event("shutdown")
def on_shutdown() -> None:
    simulator_engine.stop()
    logger.info("RESILIX simulator background engine stopped cleanly.")


@app.get("/api/v1/health", tags=["System"])
def health_check() -> dict[str, Any]:
    return {
        "status": "OK",
        "service": settings.app_name,
        "full_name": settings.app_full_name,
        "version": settings.app_version,
        "timestamp": utc_now_iso(),
    }


app.include_router(api_router)

# Serve built frontend static assets if available
FRONTEND_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
if FRONTEND_DIST.exists():
    assets_dir = FRONTEND_DIST / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def serve_spa(full_path: str) -> Any:
        if full_path.startswith("api/") or full_path in ("docs", "redoc", "openapi.json"):
            return JSONResponse(status_code=404, content={"detail": "Not Found"})
        candidate = FRONTEND_DIST / full_path
        if full_path and candidate.exists() and candidate.is_file():
            return FileResponse(str(candidate))
        index_file = FRONTEND_DIST / "index.html"
        if index_file.exists():
            return FileResponse(str(index_file))
        return JSONResponse(status_code=404, content={"detail": "Frontend build not found"})

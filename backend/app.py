"""
VerityOS Backend — FastAPI Application — Member 3.

Entry point for the backend server.  Configures CORS, registers routes,
and provides global exception handling.

Start the server:
    cd VerityOS_Vihaan_DTU
    uvicorn backend.app:app --reload --host 0.0.0.0 --port 8000

Or:
    python -m backend.app
"""

from __future__ import annotations

import logging
import sys

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend import config, auth_db
from backend.models.responses import HealthResponse
from backend.routes.analyze import router as analyze_router
from backend.routes.auth import router as auth_router

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG if config.DEBUG else logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("verityos.backend")

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title=config.APP_TITLE,
    version=config.APP_VERSION,
    description=config.APP_DESCRIPTION,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ---------------------------------------------------------------------------
# CORS — allow frontend origins
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Global exception handler — catch-all for unhandled errors
# ---------------------------------------------------------------------------

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Return a structured JSON error instead of a bare 500 page."""
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={
            "task_id": "unknown",
            "status": "ERROR",
            "query": "",
            "decision": None,
            "trust_score": None,
            "trust_grade": None,
            "claims": [],
            "evidence": [],
            "verification_results": [],
            "trust_evaluation": None,
            "provenance": None,
            "limitations": [],
            "errors": [f"Internal server error: {exc}"],
        },
    )

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get(
    "/api/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Returns the backend service status, name and version.",
    tags=["System"],
)
def health_check() -> HealthResponse:
    """GET /api/health — simple liveness probe."""
    return HealthResponse(
        status="healthy",
        service="verityos-backend",
        version=config.APP_VERSION,
    )


# Mount routers under /api
app.include_router(analyze_router, prefix="/api", tags=["Analysis"])
app.include_router(auth_router, prefix="/api/auth", tags=["Authentication"])

# ---------------------------------------------------------------------------
# Startup log & initialization
# ---------------------------------------------------------------------------

@app.on_event("startup")
def on_startup() -> None:
    # Initialize authentication SQLite database
    auth_db.init_db()
    mode = "MOCK" if config.USE_MOCK_PIPELINE else "LIVE"
    logger.info(
        "VerityOS backend v%s started  mode=%s  cors=%s",
        config.APP_VERSION,
        mode,
        config.CORS_ORIGINS,
    )

# ---------------------------------------------------------------------------
# Direct execution: python -m backend.app
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend.app:app",
        host=config.HOST,
        port=config.PORT,
        reload=config.DEBUG,
    )

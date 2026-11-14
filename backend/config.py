"""
Backend configuration — Member 3.

Loads settings from environment variables.
Secrets and API keys must NEVER be committed.
"""

import os
from dotenv import load_dotenv

load_dotenv()  # reads .env in project root if present

# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------
HOST: str = os.getenv("BACKEND_HOST", "0.0.0.0")
PORT: int = int(os.getenv("BACKEND_PORT", "8000"))
DEBUG: bool = os.getenv("BACKEND_DEBUG", "false").lower() == "true"

# ---------------------------------------------------------------------------
# CORS — allowed frontend origins
# ---------------------------------------------------------------------------
_cors_raw: str = os.getenv("CORS_ORIGINS", "http://localhost:3000")
CORS_ORIGINS: list[str] = [o.strip() for o in _cors_raw.split(",") if o.strip()]

# ---------------------------------------------------------------------------
# Pipeline mode
# ---------------------------------------------------------------------------
# When True the backend uses a built-in mock pipeline instead of
# importing agents.orchestrator.execute_pipeline.  Useful for frontend
# development before Member 1's code is available.
USE_MOCK_PIPELINE: bool = os.getenv("USE_MOCK_PIPELINE", "true").lower() == "true"

# ---------------------------------------------------------------------------
# Authentication & Database
# ---------------------------------------------------------------------------
AUTH_DB_PATH: str = os.getenv("AUTH_DB_PATH", os.path.join(os.path.dirname(__file__), "data", "auth.db"))
AUTH_TOKEN_EXPIRE_HOURS: int = int(os.getenv("AUTH_TOKEN_EXPIRE_HOURS", "24"))
AUTH_SECRET_KEY: str = os.getenv("AUTH_SECRET_KEY", "verityos-auth-secret-key-change-in-production")
# Protect /api/analyze: if False, allow unauthenticated access (dev/testing mode)
REQUIRE_AUTH_FOR_ANALYZE: bool = os.getenv("REQUIRE_AUTH_FOR_ANALYZE", "false").lower() == "true"

# ---------------------------------------------------------------------------
# App metadata
# ---------------------------------------------------------------------------
APP_TITLE: str = "VerityOS Backend API"
APP_VERSION: str = "0.1.0"
APP_DESCRIPTION: str = (
    "Backend API for VerityOS — a Trust-Aware Autonomous AI Operating System. "
    "Accepts user queries, orchestrates the analysis pipeline, and returns "
    "structured trust-evaluated results."
)

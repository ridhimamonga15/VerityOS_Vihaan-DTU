"""
FastAPI authentication dependencies — Member 3.

Provides dependencies to extract and validate Bearer tokens for protected routes.
"""

from __future__ import annotations

from typing import Optional, Any
from fastapi import Header, HTTPException, status

from backend import config, auth_db


def extract_token_from_header(authorization: Optional[str]) -> Optional[str]:
    """Parse 'Bearer <token>' from the Authorization header."""
    if not authorization:
        return None
    parts = authorization.strip().split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


def get_current_user(authorization: Optional[str] = Header(None)) -> dict[str, Any]:
    """
    Strict dependency: Requires a valid bearer token.
    Raises 401 Unauthorized if missing, expired, or invalid.
    """
    token = extract_token_from_header(authorization)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = auth_db.get_session_user(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def get_user_for_analyze(authorization: Optional[str] = Header(None)) -> Optional[dict[str, Any]]:
    """
    Configurable dependency for /api/analyze:
    - If REQUIRE_AUTH_FOR_ANALYZE is True: requires a valid token.
    - If REQUIRE_AUTH_FOR_ANALYZE is False: permits unauthenticated access for development/tests,
      but still validates token if provided.
    """
    if config.REQUIRE_AUTH_FOR_ANALYZE:
        return get_current_user(authorization)

    token = extract_token_from_header(authorization)
    if token:
        return auth_db.get_session_user(token)
    return None

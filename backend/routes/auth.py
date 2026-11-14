"""
Authentication routes for VerityOS — Member 3.

Endpoints:
- POST /api/auth/signup: Register a new account
- POST /api/auth/login: Authenticate credentials and receive token
- GET  /api/auth/me: Retrieve current authenticated user profile
- POST /api/auth/logout: Revoke authentication session
"""

from __future__ import annotations

import logging
from typing import Optional, Any
from fastapi import APIRouter, Depends, Header, HTTPException, status

from backend import auth_db, security
from backend.models.auth import (
    SignupRequest,
    LoginRequest,
    UserOut,
    AuthResponse,
    LogoutResponse,
)
from backend.dependencies import get_current_user, extract_token_from_header

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "/signup",
    response_model=AuthResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    description="Registers a new user, hashes password securely, prevents duplicate email, and returns auth token.",
    responses={
        400: {"description": "Passwords do not match or invalid input."},
        409: {"description": "Email already registered."},
    },
)
def signup(request: SignupRequest) -> AuthResponse:
    """Register a new user account."""
    # 1. Check if email already registered
    existing = auth_db.get_user_by_email(request.email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )

    # 2. Hash password securely
    hashed = security.hash_password(request.password)

    # 3. Create user in SQLite
    user = auth_db.create_user(
        name=request.name,
        email=request.email,
        password_hash=hashed,
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )

    # 4. Create active session token
    token = security.generate_token()
    auth_db.create_session(user_id=user["id"], token=token)

    logger.info("New user registered: %s (id=%s)", user["email"], user["id"])
    return AuthResponse(
        message="User registered successfully",
        token=token,
        token_type="bearer",
        user=UserOut(**user),
    )


@router.post(
    "/login",
    response_model=AuthResponse,
    status_code=status.HTTP_200_OK,
    summary="User login",
    description="Authenticates credentials and returns a secure bearer token.",
    responses={
        401: {"description": "Invalid email or password."},
    },
)
def login(request: LoginRequest) -> AuthResponse:
    """Authenticate email and password."""
    user_record = auth_db.get_user_by_email(request.email)
    if not user_record:
        # Avoid giving hints about whether the email exists
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not security.verify_password(request.password, user_record["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Generate new session token
    token = security.generate_token()
    auth_db.create_session(user_id=user_record["id"], token=token)

    user_out = {
        "id": user_record["id"],
        "name": user_record["name"],
        "email": user_record["email"],
        "created_at": user_record["created_at"],
    }
    logger.info("User login successful: %s (id=%s)", user_out["email"], user_out["id"])
    return AuthResponse(
        message="Login successful",
        token=token,
        token_type="bearer",
        user=UserOut(**user_out),
    )


@router.get(
    "/me",
    response_model=UserOut,
    status_code=status.HTTP_200_OK,
    summary="Get current user",
    description="Returns profile information for the authenticated user.",
    responses={
        401: {"description": "Missing, expired, or invalid token."},
    },
)
def get_me(current_user: dict[str, Any] = Depends(get_current_user)) -> UserOut:
    """Retrieve profile of the currently authenticated user."""
    return UserOut(**current_user)


@router.post(
    "/logout",
    response_model=LogoutResponse,
    status_code=status.HTTP_200_OK,
    summary="User logout",
    description="Revokes the current authentication token/session.",
)
def logout(authorization: Optional[str] = Header(None)) -> LogoutResponse:
    """Invalidate current session token."""
    token = extract_token_from_header(authorization)
    if token:
        auth_db.delete_session(token)
    return LogoutResponse(message="Logged out successfully")

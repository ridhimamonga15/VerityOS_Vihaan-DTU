"""
Authentication Pydantic schemas — Member 3.

Defines request and response schemas for Signup, Login, Current User, and Logout.
Sensitive fields like passwords or password hashes are NEVER exposed in responses.
Uses standard regex validation for email without external package dependencies.
"""

from __future__ import annotations

import re
from pydantic import BaseModel, Field, field_validator, model_validator

# Standard RFC-compliant email pattern
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


class SignupRequest(BaseModel):
    """
    Request payload for POST /api/auth/signup.
    """
    name: str = Field(..., min_length=1, max_length=100, description="User full name")
    email: str = Field(..., description="Unique email address")
    password: str = Field(..., min_length=6, max_length=128, description="Password (at least 6 characters)")
    confirm_password: str = Field(..., min_length=6, max_length=128, description="Password confirmation")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Name cannot be empty.")
        return cleaned

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        cleaned = v.strip().lower()
        if not EMAIL_REGEX.match(cleaned):
            raise ValueError("Invalid email format.")
        return cleaned

    @model_validator(mode="after")
    def check_passwords_match(self) -> SignupRequest:
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match.")
        return self


class LoginRequest(BaseModel):
    """
    Request payload for POST /api/auth/login.
    """
    email: str = Field(..., description="Registered email address")
    password: str = Field(..., min_length=1, description="Account password")

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        cleaned = v.strip().lower()
        if not EMAIL_REGEX.match(cleaned):
            raise ValueError("Invalid email format.")
        return cleaned


class UserOut(BaseModel):
    """
    Public user representation.
    NEVER includes password or password_hash.
    """
    id: str
    name: str
    email: str
    created_at: str


class AuthResponse(BaseModel):
    """
    Response returned on successful signup or login.
    """
    message: str
    token: str
    token_type: str = "bearer"
    user: UserOut


class LogoutResponse(BaseModel):
    """
    Response returned on successful logout.
    """
    message: str = "Logged out successfully"

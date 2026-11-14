"""
Security and cryptographic utilities for VerityOS — Member 3.

Handles password hashing and verification using PBKDF2-HMAC-SHA256
with 100,000 iterations and cryptographically secure random salts.
Also handles secure token generation.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

ITERATIONS = 100_000
ALGORITHM = "sha256"
SALT_BYTES = 16


def hash_password(plain_password: str) -> str:
    """
    Hash a plain-text password using PBKDF2-HMAC-SHA256.

    Returns:
        Formatted string: 'pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>'
    """
    salt = secrets.token_bytes(SALT_BYTES)
    key = hashlib.pbkdf2_hmac(
        ALGORITHM,
        plain_password.encode("utf-8"),
        salt,
        ITERATIONS,
    )
    return f"pbkdf2_sha256${ITERATIONS}${salt.hex()}${key.hex()}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain password against a stored hash string using constant-time comparison.
    """
    try:
        parts = hashed_password.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return False

        iterations = int(parts[1])
        salt = bytes.fromhex(parts[2])
        expected_key = bytes.fromhex(parts[3])

        computed_key = hashlib.pbkdf2_hmac(
            ALGORITHM,
            plain_password.encode("utf-8"),
            salt,
            iterations,
        )
        return hmac.compare_digest(computed_key, expected_key)
    except Exception:
        return False


def generate_token() -> str:
    """Generate a high-entropy cryptographically secure bearer token."""
    return secrets.token_urlsafe(32)

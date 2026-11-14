"""
Authentication integration tests — Member 3.

Tests:
- Signup (success, password mismatch, invalid email, duplicate registration)
- Login (success, wrong password, non-existent email)
- Current user /me (valid token, missing token, invalid token)
- Logout (session revocation)
- Password security (hashing verification, no plaintext)
- Protected analyze route (configurable behavior)
"""

import os
import sqlite3
import tempfile
import unittest
from fastapi import HTTPException
from pydantic import ValidationError

from backend import auth_db, config, security
from backend.models.auth import SignupRequest, LoginRequest
from backend.models.requests import AnalyzeRequest
from backend.routes.auth import signup, login, get_me, logout
from backend.routes.analyze import analyze
from backend.dependencies import get_current_user, get_user_for_analyze


class TestAuthentication(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Use an isolated temporary SQLite database for tests
        cls.temp_db_fd, cls.temp_db_path = tempfile.mkstemp(suffix="_auth_test.db")
        os.close(cls.temp_db_fd)
        cls.original_db_path = config.AUTH_DB_PATH
        config.AUTH_DB_PATH = cls.temp_db_path
        auth_db.init_db(cls.temp_db_path)

    @classmethod
    def tearDownClass(cls):
        config.AUTH_DB_PATH = cls.original_db_path
        if os.path.exists(cls.temp_db_path):
            try:
                os.remove(cls.temp_db_path)
            except OSError:
                pass

    def test_01_signup_success(self):
        """User can sign up successfully and receive auth token and profile."""
        req = SignupRequest(
            name="Alice Walker",
            email="alice@example.com",
            password="SecurePassword123!",
            confirm_password="SecurePassword123!",
        )
        res = signup(req)
        self.assertEqual(res.message, "User registered successfully")
        self.assertTrue(len(res.token) > 20)
        self.assertEqual(res.token_type, "bearer")
        self.assertEqual(res.user.name, "Alice Walker")
        self.assertEqual(res.user.email, "alice@example.com")
        self.assertTrue(res.user.id.startswith("user_"))

    def test_02_signup_password_mismatch(self):
        """Signup fails validation if passwords do not match."""
        with self.assertRaises(ValidationError) as ctx:
            SignupRequest(
                name="Bob Walker",
                email="bob@example.com",
                password="PasswordOne123",
                confirm_password="PasswordTwo123",
            )
        self.assertIn("Passwords do not match", str(ctx.exception))

    def test_03_signup_invalid_email(self):
        """Signup fails validation for malformed email."""
        with self.assertRaises(ValidationError) as ctx:
            SignupRequest(
                name="Bad Email User",
                email="not-an-email",
                password="Password123",
                confirm_password="Password123",
            )
        self.assertIn("Invalid email format", str(ctx.exception))

    def test_04_signup_duplicate_email(self):
        """Prevent duplicate email registration (case-insensitive) with 409 Conflict."""
        req = SignupRequest(
            name="Alice Duplicate",
            email="ALICE@EXAMPLE.COM",  # uppercase variation of alice@example.com
            password="AnotherPassword123",
            confirm_password="AnotherPassword123",
        )
        with self.assertRaises(HTTPException) as ctx:
            signup(req)
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertIn("already exists", ctx.exception.detail)

    def test_05_login_success(self):
        """User can log in with correct credentials and receive a new session token."""
        req = LoginRequest(
            email="alice@example.com",
            password="SecurePassword123!",
        )
        res = login(req)
        self.assertEqual(res.message, "Login successful")
        self.assertTrue(len(res.token) > 20)
        self.assertEqual(res.user.email, "alice@example.com")

    def test_06_login_incorrect_password(self):
        """Login fails with 401 when given an incorrect password."""
        req = LoginRequest(
            email="alice@example.com",
            password="WrongPassword999!",
        )
        with self.assertRaises(HTTPException) as ctx:
            login(req)
        self.assertEqual(ctx.exception.status_code, 401)
        self.assertEqual(ctx.exception.detail, "Invalid email or password.")

    def test_07_login_nonexistent_email(self):
        """Login fails with 401 for an email that does not exist."""
        req = LoginRequest(
            email="ghost@example.com",
            password="SomePassword123!",
        )
        with self.assertRaises(HTTPException) as ctx:
            login(req)
        self.assertEqual(ctx.exception.status_code, 401)
        self.assertEqual(ctx.exception.detail, "Invalid email or password.")

    def test_08_get_me_valid_token(self):
        """GET /api/auth/me returns user profile with valid Bearer token."""
        login_res = login(LoginRequest(email="alice@example.com", password="SecurePassword123!"))
        token = login_res.token

        user = get_current_user(authorization=f"Bearer {token}")
        self.assertEqual(user["email"], "alice@example.com")
        self.assertEqual(user["name"], "Alice Walker")

    def test_09_get_me_missing_token(self):
        """GET /api/auth/me fails with 401 when Authorization header is absent."""
        with self.assertRaises(HTTPException) as ctx:
            get_current_user(authorization=None)
        self.assertEqual(ctx.exception.status_code, 401)

    def test_10_get_me_invalid_token(self):
        """GET /api/auth/me fails with 401 when token is invalid or fabricated."""
        with self.assertRaises(HTTPException) as ctx:
            get_current_user(authorization="Bearer forged_token_12345")
        self.assertEqual(ctx.exception.status_code, 401)

    def test_11_logout_invalidates_token(self):
        """POST /api/auth/logout invalidates session, subsequent requests return 401."""
        login_res = login(LoginRequest(email="alice@example.com", password="SecurePassword123!"))
        token = login_res.token

        # Verify token works before logout
        user_before = get_current_user(authorization=f"Bearer {token}")
        self.assertIsNotNone(user_before)

        # Logout
        logout_res = logout(authorization=f"Bearer {token}")
        self.assertEqual(logout_res.message, "Logged out successfully")

        # Verify token is now rejected with 401
        with self.assertRaises(HTTPException) as ctx:
            get_current_user(authorization=f"Bearer {token}")
        self.assertEqual(ctx.exception.status_code, 401)

    def test_12_password_never_stored_in_plaintext(self):
        """Passwords in SQLite are hashed with PBKDF2-HMAC-SHA256 and never in plaintext."""
        with sqlite3.connect(self.temp_db_path) as conn:
            cursor = conn.execute("SELECT password_hash FROM users WHERE email = 'alice@example.com';")
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            stored_hash = row[0]

            # Verify it is not the plaintext
            self.assertNotEqual(stored_hash, "SecurePassword123!")
            # Verify it has PBKDF2 format
            self.assertTrue(stored_hash.startswith("pbkdf2_sha256$100000$"))
            # Verify security.verify_password works on it
            self.assertTrue(security.verify_password("SecurePassword123!", stored_hash))
            self.assertFalse(security.verify_password("WrongPassword", stored_hash))

    def test_13_analyze_endpoint_configurable_auth(self):
        """
        Verify /api/analyze authentication is configurable:
        - When REQUIRE_AUTH_FOR_ANALYZE=false: unauthenticated access works (backward-compatible).
        - When REQUIRE_AUTH_FOR_ANALYZE=true: unauthenticated access raises 401, authenticated succeeds.
        """
        analyze_req = AnalyzeRequest(query="Market analysis test query")

        # 1. Dev/MVP mode (REQUIRE_AUTH_FOR_ANALYZE = False)
        config.REQUIRE_AUTH_FOR_ANALYZE = False
        res_open = analyze(analyze_req, current_user=None)
        self.assertEqual(res_open.status, "SUCCESS")

        # 2. Strict protected mode (REQUIRE_AUTH_FOR_ANALYZE = True)
        config.REQUIRE_AUTH_FOR_ANALYZE = True
        try:
            # Unauthenticated should fail with 401
            with self.assertRaises(HTTPException) as ctx:
                get_user_for_analyze(authorization=None)
            self.assertEqual(ctx.exception.status_code, 401)

            # Authenticated should succeed
            login_res = login(LoginRequest(email="alice@example.com", password="SecurePassword123!"))
            auth_user = get_user_for_analyze(authorization=f"Bearer {login_res.token}")
            self.assertIsNotNone(auth_user)

            res_auth = analyze(analyze_req, current_user=auth_user)
            self.assertEqual(res_auth.status, "SUCCESS")
        finally:
            config.REQUIRE_AUTH_FOR_ANALYZE = False


if __name__ == "__main__":
    unittest.main()

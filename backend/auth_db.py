"""
Authentication database access layer using SQLite — Member 3.

Manages users and sessions in a dedicated SQLite database.
Never touches pipeline schemas or agent data.
"""

from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, Any

from backend import config


def get_db_path(db_path: Optional[str] = None) -> str:
    """Return the configured path to the authentication SQLite database."""
    target_path = db_path or config.AUTH_DB_PATH
    os.makedirs(os.path.dirname(os.path.abspath(target_path)), exist_ok=True)
    return target_path


def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Get a SQLite connection with row_factory enabled."""
    conn = sqlite3.connect(get_db_path(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """Create authentication tables if they do not exist."""
    with get_connection(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()


def create_user(
    name: str,
    email: str,
    password_hash: str,
    db_path: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """
    Insert a new user. Returns user dict (without password) or None if email already exists.
    """
    user_id = f"user_{uuid.uuid4().hex[:12]}"
    created_at = datetime.now(timezone.utc).isoformat()
    clean_email = email.strip().lower()

    try:
        with get_connection(db_path) as conn:
            conn.execute(
                """
                INSERT INTO users (id, name, email, password_hash, created_at)
                VALUES (?, ?, ?, ?, ?);
                """,
                (user_id, name.strip(), clean_email, password_hash, created_at),
            )
            conn.commit()
            return {
                "id": user_id,
                "name": name.strip(),
                "email": clean_email,
                "created_at": created_at,
            }
    except sqlite3.IntegrityError:
        # Unique constraint on email failed
        return None


def get_user_by_email(email: str, db_path: Optional[str] = None) -> Optional[dict[str, Any]]:
    """
    Retrieve user record by email, including password_hash for credential verification.
    """
    clean_email = email.strip().lower()
    with get_connection(db_path) as conn:
        cursor = conn.execute(
            "SELECT id, name, email, password_hash, created_at FROM users WHERE email = ?;",
            (clean_email,),
        )
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None


def get_user_by_id(user_id: str, db_path: Optional[str] = None) -> Optional[dict[str, Any]]:
    """
    Retrieve user record by ID (excludes password_hash).
    """
    with get_connection(db_path) as conn:
        cursor = conn.execute(
            "SELECT id, name, email, created_at FROM users WHERE id = ?;",
            (user_id,),
        )
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None


def create_session(
    user_id: str,
    token: str,
    expire_hours: Optional[int] = None,
    db_path: Optional[str] = None,
) -> str:
    """
    Store an active session token for a user.
    """
    hours = expire_hours if expire_hours is not None else config.AUTH_TOKEN_EXPIRE_HOURS
    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(hours=hours)).isoformat()
    created_at = now.isoformat()

    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO sessions (token, user_id, created_at, expires_at)
            VALUES (?, ?, ?, ?);
            """,
            (token, user_id, created_at, expires_at),
        )
        conn.commit()
    return token


def get_session_user(token: str, db_path: Optional[str] = None) -> Optional[dict[str, Any]]:
    """
    Validate token against active sessions. Returns user dict (without password)
    if valid and not expired, else None.
    """
    now_str = datetime.now(timezone.utc).isoformat()
    with get_connection(db_path) as conn:
        cursor = conn.execute(
            """
            SELECT u.id, u.name, u.email, u.created_at, s.expires_at
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.token = ? AND s.expires_at > ?;
            """,
            (token, now_str),
        )
        row = cursor.fetchone()
        if row:
            return {
                "id": row["id"],
                "name": row["name"],
                "email": row["email"],
                "created_at": row["created_at"],
            }
        return None


def delete_session(token: str, db_path: Optional[str] = None) -> bool:
    """
    Remove session token on logout. Returns True if a session was deleted.
    """
    with get_connection(db_path) as conn:
        cursor = conn.execute("DELETE FROM sessions WHERE token = ?;", (token,))
        conn.commit()
        return cursor.rowcount > 0

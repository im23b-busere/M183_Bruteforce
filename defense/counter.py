# Defense 3.2: Counter-Limit (Account Lockout)
# This module tracks failed login attempts and locks accounts after a threshold

import time
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "db" / "users.sqlite"

# Configuration
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 300  # 5 minutes


def get_db_connection():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def is_account_locked(username):
    """Check if account is currently locked. Returns (locked: bool, remaining_seconds: int)."""
    conn = get_db_connection()
    try:
        cur = conn.execute(
            "SELECT failed_attempts, locked_until FROM users WHERE username = ?",
            (username,)
        )
        row = cur.fetchone()
        if not row:
            return False, 0
        
        locked_until = row["locked_until"]
        if locked_until > 0:
            if time.time() < locked_until:
                remaining = int(locked_until - time.time())
                return True, remaining
            else:
                # lockout expired, reset
                reset_failed_attempts(username)
                return False, 0
        
        return False, 0
    finally:
        conn.close()


def increment_failed_attempts(username):
    """Increment failed attempt counter. Lock account if threshold exceeded."""
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT failed_attempts FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if not row:
            return
        
        new_count = row["failed_attempts"] + 1
        locked_until = 0
        
        # apply lockout if threshold exceeded
        if new_count >= MAX_FAILED_ATTEMPTS:
            locked_until = int(time.time()) + LOCKOUT_DURATION_SECONDS
        
        conn.execute(
            "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = ?",
            (new_count, locked_until, username)
        )
        conn.commit()
    finally:
        conn.close()


def reset_failed_attempts(username):
    """Reset failed attempt counter after successful login."""
    conn = get_db_connection()
    try:
        conn.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE username = ?",
            (username,)
        )
        conn.commit()
    finally:
        conn.close()

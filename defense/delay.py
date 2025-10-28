# Defense 3.1: Linear and Progressive Delay
# These functions slow down brute-force attacks by introducing delays

import time
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "db" / "users.sqlite"

# Configuration
LINEAR_DELAY_SECONDS = 1.0
PROGRESSIVE_DELAY_BASE = 1.0
PROGRESSIVE_DELAY_MULTIPLIER = 2.0


def get_failed_attempts(username):
    """Get number of failed attempts for a user."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.execute("SELECT failed_attempts FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if not row:
            return 0
        return row["failed_attempts"]
    finally:
        conn.close()


def apply_linear_delay():
    """Apply a fixed delay (e.g., 1 second) before each login attempt."""
    time.sleep(LINEAR_DELAY_SECONDS)


def apply_progressive_delay(username):
    """Apply exponentially increasing delay based on failed attempts."""
    failed_attempts = get_failed_attempts(username)
    delay = PROGRESSIVE_DELAY_BASE * (PROGRESSIVE_DELAY_MULTIPLIER ** failed_attempts)
    time.sleep(delay)

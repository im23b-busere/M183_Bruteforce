#!/usr/bin/env python3
"""
================================================================================
File:        create_db.py
Description: Database initialization script for M183 BruteForce project
             Creates SQLite database with schema and demo user accounts
Parameters:  --mode <simple|complex>, --db <path>
Author:      Cadima Lusiola
Date:        2025-10-28
================================================================================
"""

import argparse
import sqlite3
import sys
import time
from pathlib import Path
import bcrypt


def bcrypt_hash(password):
    """Return a bcrypt hash (utf-8 string)"""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def main(argv=None):
    """Create DB, apply schema and insert demo accounts.

    Modes:
      - vulnerable: store `password_plain`, leave `password_hash` NULL
      - secure: store bcrypt `password_hash`, leave `password_plain` NULL
      - both: store both `password_plain` and bcrypt `password_hash`
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode",
        choices=("vulnerable", "secure", "both"),
        default="vulnerable",
        help="Insert demo users in given mode: vulnerable (plain), secure (bcrypt), or both",
    )
    args = parser.parse_args(argv)

    mode = args.mode

    repo_root = Path(__file__).resolve().parent.parent
    db_dir = repo_root / "db"
    db_dir.mkdir(parents=True, exist_ok=True)

    db_path = db_dir / "users.sqlite"
    schema_path = db_dir / "schema.sql"

    if not schema_path.exists():
        print(f"Schema file not found: {schema_path}", file=sys.stderr)
        return 2

    # Connect (will create file if it doesn't exist)
    conn = sqlite3.connect(str(db_path))
    try:
        # Ensure foreign keys are enabled
        conn.execute("PRAGMA foreign_keys = ON;")

        # Read and execute schema
        sql = schema_path.read_text(encoding="utf-8")
        conn.executescript(sql)

        # Prepare demo users
        now = int(time.time())
        demo_users = [
            ("alice", "a2", "alice@example.com"),
            ("bob", "123", "erbu08@gmail.com"),
        ]

        cur = conn.cursor()
        for username, plain, email in demo_users:
            pw_plain = None
            pw_hash = None
            if mode == "vulnerable":
                pw_plain = plain
                pw_hash = None
            elif mode == "secure":
                pw_plain = None
                pw_hash = bcrypt_hash(plain)
            else:  # both
                pw_plain = plain
                pw_hash = bcrypt_hash(plain)

            # Insert by username 
            cur.execute(
                "INSERT OR IGNORE INTO users (username, password_plain, password_hash, email, failed_attempts, locked_until, created_at) VALUES (?, ?, ?, ?, 0, 0, ?)",
                (username, pw_plain, pw_hash, email, now),
            )

        conn.commit()
    finally:
        conn.close()

    # Print absolute path to DB as requested
    print(str(db_path.resolve()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

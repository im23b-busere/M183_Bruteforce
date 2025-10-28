#!/usr/bin/env python3
"""
================================================================================
File:        rainbow_attack.py
Description: Rainbow table attack demonstration (serial version)
             Looks up password hashes in pre-computed rainbow table
Parameters:  --db <database_path>, --table <rainbow_table.json>
Author:      Erik Buser
Date:        2025-10-28
================================================================================
"""

import argparse
import hashlib
import json
import sqlite3
import sys
from pathlib import Path


def load_rainbow_table(path):
    """Load rainbow table from JSON file. Returns dict {hash: plaintext}."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[!] Rainbow table not found: {path}", file=sys.stderr)
        sys.exit(2)
    except json.JSONDecodeError as e:
        print(f"[!] Failed to parse rainbow table JSON: {e}", file=sys.stderr)
        sys.exit(2)


def get_users(db_path):
    """Read all users from SQLite DB. Returns list of (username, password_plain) tuples."""
    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        cur = conn.execute("SELECT username, password_plain FROM users WHERE password_plain IS NOT NULL")
        users = [(row["username"], row["password_plain"]) for row in cur.fetchall()]
        conn.close()
        return users
    except sqlite3.Error as e:
        print(f"[!] Database error: {e}", file=sys.stderr)
        sys.exit(2)


def main():
    parser = argparse.ArgumentParser(description="Rainbow table attack demo")
    parser.add_argument(
        "--db",
        default="db/users.sqlite",
        help="Path to SQLite database (default: db/users.sqlite)",
    )
    parser.add_argument(
        "--table",
        default="attack/rainbow_table.json",
        help="Path to rainbow table JSON (default: attack/rainbow_table.json)",
    )
    args = parser.parse_args()

    db_path = Path(args.db)
    table_path = Path(args.table)

    if not db_path.exists():
        print(f"[!] Database not found: {db_path}", file=sys.stderr)
        return 2

    print("=" * 70)
    print("RAINBOW TABLE ATTACK DEMO")
    print("=" * 70)
    print()


    rainbow_table = load_rainbow_table(table_path)
    print(f"[+] Loaded rainbow table with {len(rainbow_table):,} entries")

    users = get_users(db_path)
    print(f"[+] Found {len(users)} users with plaintext passwords in DB")
    print()

    found = 0
    not_found = 0

    for username, password_plain in users:
        # Simulate attacker computing hash of stored password
        # In real scenario, attacker would have obtained the hash directly
        pwd_hash = hashlib.sha1(password_plain.encode("utf-8")).hexdigest()
        
        if pwd_hash in rainbow_table:
            cracked = rainbow_table[pwd_hash]
            print(f"[CRACKED] {username}: {cracked} (hash: {pwd_hash[:16]}...)")
            found += 1
        else:
            print(f"[NOT FOUND] {username}: hash {pwd_hash[:16]}... not in rainbow table")
            not_found += 1

    print()
    print("=" * 70)
    print(f"Results: {found} cracked, {not_found} not found")
    print("=" * 70)
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

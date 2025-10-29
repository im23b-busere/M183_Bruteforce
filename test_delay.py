#!/usr/bin/env python3
"""
Test script to verify delay and counter mechanisms
"""

import sqlite3
import time
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "db" / "users.sqlite"

def get_user_info(username):
    """Get current failed_attempts and locked_until for a user."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.execute("SELECT failed_attempts, locked_until FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if row:
            return {
                "failed_attempts": row["failed_attempts"],
                "locked_until": row["locked_until"],
                "locked": row["locked_until"] > time.time()
            }
        return None
    finally:
        conn.close()

def calculate_delay(failed_attempts, mode="progressive"):
    """Calculate what delay would be applied."""
    if mode == "linear":
        return 1.0
    else:  # progressive
        return 1.0 * (2.0 ** failed_attempts)

def main():
    username = "alice"
    
    print("=" * 70)
    print("DELAY & COUNTER TEST")
    print("=" * 70)
    print()
    
    info = get_user_info(username)
    if not info:
        print(f"User '{username}' not found in database!")
        return
    
    print(f"Current state for user '{username}':")
    print(f"  Failed attempts: {info['failed_attempts']}")
    print(f"  Locked: {'Yes' if info['locked'] else 'No'}")
    if info['locked']:
        remaining = int(info['locked_until'] - time.time())
        print(f"  Locked for: {remaining} seconds")
    print()
    
    print("Progressive delay calculation:")
    print("-" * 70)
    for i in range(6):
        delay = calculate_delay(i)
        print(f"  After {i} failed attempts: {delay:.1f}s delay")
    print()
    
    print("Note: In the current implementation, the delay is calculated")
    print("BEFORE incrementing the counter, so there's always a 1-attempt lag.")
    print()
    print("Example flow:")
    print("  1st attempt: failed_attempts=0 → delay=1s → fails → counter=1")
    print("  2nd attempt: failed_attempts=1 → delay=2s → fails → counter=2")
    print("  3rd attempt: failed_attempts=2 → delay=4s → fails → counter=3")
    print("  4th attempt: failed_attempts=3 → delay=8s → fails → counter=4")
    print("  5th attempt: failed_attempts=4 → delay=16s → fails → counter=5 → LOCKED!")
    print()

if __name__ == "__main__":
    main()

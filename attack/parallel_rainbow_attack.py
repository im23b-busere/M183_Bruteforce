#!/usr/bin/env python3
"""
================================================================================
File:        parallel_rainbow_attack.py
Description: Parallelized rainbow table attack using multi-processing
             Distributes hash lookups across multiple worker processes
             for faster cracking of password hashes
Parameters:  --db <database>, --table <rainbow_table.json>, --workers <int>
Author:      Erik Buser
Date:        2025-10-28
================================================================================
"""

import argparse
import hashlib
import json
import sqlite3
import sys
import multiprocessing
import time
from pathlib import Path
from itertools import islice


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


def worker_process(worker_id, num_workers, users, rainbow_table, result_queue):
    """Worker process that checks a subset of users against rainbow table.
    
    Args:
        worker_id: ID of this worker (0-based)
        num_workers: Total number of workers
        users: List of (username, password_plain) tuples
        rainbow_table: Dict of {hash: plaintext}
        result_queue: Queue to send results back to main process
    """
    found = 0
    not_found = 0
    
    # Each worker handles every Nth user (where N = num_workers)
    my_users = list(islice(users, worker_id, None, num_workers))
    
    print(f"[Worker {worker_id}] Processing {len(my_users)} users...")
    
    for username, password_plain in my_users:
        # Compute hash of stored password
        pwd_hash = hashlib.sha1(password_plain.encode("utf-8")).hexdigest()
        
        if pwd_hash in rainbow_table:
            cracked = rainbow_table[pwd_hash]
            result_queue.put({
                "worker_id": worker_id,
                "status": "CRACKED",
                "username": username,
                "password": cracked,
                "hash": pwd_hash
            })
            found += 1
        else:
            result_queue.put({
                "worker_id": worker_id,
                "status": "NOT_FOUND",
                "username": username,
                "hash": pwd_hash
            })
            not_found += 1
    
    print(f"[Worker {worker_id}] Complete: {found} cracked, {not_found} not found")
    result_queue.put({
        "worker_id": worker_id,
        "status": "DONE",
        "found": found,
        "not_found": not_found
    })


def main():
    parser = argparse.ArgumentParser(description="Parallel rainbow table attack")
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
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Number of worker processes (default: 4)",
    )
    args = parser.parse_args()

    db_path = Path(args.db)
    table_path = Path(args.table)

    if not db_path.exists():
        print(f"[!] Database not found: {db_path}", file=sys.stderr)
        return 2

    print("=" * 70)
    print("PARALLEL RAINBOW TABLE ATTACK")
    print("=" * 70)
    print()

    # Load rainbow table (shared across all workers)
    print(f"[Main] Loading rainbow table from {table_path}...")
    rainbow_table = load_rainbow_table(table_path)
    print(f"[+] Loaded rainbow table with {len(rainbow_table):,} entries")

    # Get users from database
    print(f"[Main] Loading users from {db_path}...")
    users = get_users(db_path)
    print(f"[+] Found {len(users)} users with plaintext passwords in DB")
    print()

    # Create result queue
    result_queue = multiprocessing.Queue()

    # Start worker processes
    print(f"[Main] Starting {args.workers} worker processes...")
    processes = []
    start_time = time.time()

    for worker_id in range(args.workers):
        p = multiprocessing.Process(
            target=worker_process,
            args=(worker_id, args.workers, users, rainbow_table, result_queue),
        )
        p.start()
        processes.append(p)
        print(f"[Main] Started worker {worker_id} (PID {p.pid})")

    print()
    print("=" * 70)
    print("RESULTS")
    print("=" * 70)

    # Collect results
    total_found = 0
    total_not_found = 0
    workers_done = 0
    cracked_passwords = []

    while workers_done < args.workers:
        result = result_queue.get()
        
        if result["status"] == "CRACKED":
            print(f"[CRACKED] {result['username']}: {result['password']} (hash: {result['hash'][:16]}...)")
            cracked_passwords.append((result['username'], result['password']))
        elif result["status"] == "NOT_FOUND":
            print(f"[NOT FOUND] {result['username']}: hash {result['hash'][:16]}... not in rainbow table")
        elif result["status"] == "DONE":
            total_found += result["found"]
            total_not_found += result["not_found"]
            workers_done += 1

    # Wait for all workers to finish
    for p in processes:
        p.join()

    elapsed = time.time() - start_time

    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Total users processed: {len(users)}")
    print(f"Passwords cracked: {total_found}")
    print(f"Passwords not found: {total_not_found}")
    print(f"Success rate: {(total_found/len(users)*100) if len(users) > 0 else 0:.1f}%")
    print(f"Total time: {elapsed:.2f}s")
    print(f"Speed: {len(users)/elapsed:.1f} users/second")
    print("=" * 70)
    
    if cracked_passwords:
        print()
        print("Cracked passwords:")
        for username, password in cracked_passwords:
            print(f"  {username}: {password}")
    
    return 0


if __name__ == "__main__":
    # Required for Windows multiprocessing
    multiprocessing.freeze_support()
    raise SystemExit(main())

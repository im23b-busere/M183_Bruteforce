#!/usr/bin/env python3
"""
Test script to measure actual server response times with delays
"""

import requests
import time

TARGET = "http://127.0.0.1:5001/login"  # Secure server with delays
USERNAME = "alice"
WRONG_PASSWORD = "wrongpass"

def test_attempt(attempt_num):
    """Make a login attempt and measure response time."""
    payload = {
        "username": USERNAME,
        "password": WRONG_PASSWORD,
        "g-recaptcha-response": "test"  # Won't work without real CAPTCHA
    }
    
    start = time.time()
    try:
        r = requests.post(TARGET, json=payload, timeout=30)
        elapsed = time.time() - start
        return elapsed, r.status_code
    except Exception as e:
        elapsed = time.time() - start
        return elapsed, str(e)

def main():
    print("=" * 70)
    print("TESTING PROGRESSIVE DELAY ON SECURE SERVER")
    print("=" * 70)
    print(f"Target: {TARGET}")
    print(f"Username: {USERNAME}")
    print()
    print("Making 5 failed login attempts to observe delay progression...")
    print()
    
    for i in range(1, 6):
        print(f"Attempt {i}...", end=" ", flush=True)
        elapsed, status = test_attempt(i)
        print(f"completed in {elapsed:.2f}s (status: {status})")
        
    print()
    print("Expected delays (progressive):")
    print("  1st: ~1s, 2nd: ~2s, 3rd: ~4s, 4th: ~8s, 5th: ~16s")
    print()
    print("Note: CAPTCHA might cause all attempts to fail immediately.")
    print("To properly test, temporarily disable CAPTCHA in secure_server.py")

if __name__ == "__main__":
    main()

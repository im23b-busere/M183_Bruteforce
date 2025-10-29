"""
================================================================================
File:        secure_server.py
Description: Secured Flask server with all defense mechanisms active
             Implements delays, account lockout, CAPTCHA, and logging
Parameters:  Environment variables:
             - DEFENSE_MODE: "linear" or "progressive" (default: progressive)
             Runs on http://127.0.0.1:5001 by default
Author:      Raiyan Mahfuz
Date:        2025-10-28
================================================================================
"""

from flask import Flask, render_template, request, jsonify, session
import sqlite3
from pathlib import Path
import secrets
import sys
import os
import bcrypt
from datetime import timedelta

# add parent directory to path so we can import defense modules
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# import defense mechanisms
from defense.delay import apply_progressive_delay, apply_linear_delay
from defense.counter import is_account_locked, increment_failed_attempts, reset_failed_attempts
from defense.logging import log_auth_attempt
from defense.captcha import verify_recaptcha


app = Flask(__name__, template_folder="templates")

# Configuration: Defense mechanisms (can be toggled via environment variables)
DEFENSE_MODE = os.environ.get("DEFENSE_MODE", "progressive")  # "linear" or "progressive"
ENABLE_DELAY = os.environ.get("ENABLE_DELAY", "true").lower() == "true"
ENABLE_COUNTER = os.environ.get("ENABLE_COUNTER", "true").lower() == "true"
ENABLE_CAPTCHA = os.environ.get("ENABLE_CAPTCHA", "true").lower() == "true"
ENABLE_LOGGING = os.environ.get("ENABLE_LOGGING", "true").lower() == "true"

# secure session configuration
SESSION_KEY_FILE = Path(__file__).resolve().parent / ".session_key"
if SESSION_KEY_FILE.exists():
    app.secret_key = SESSION_KEY_FILE.read_bytes()
else:
    app.secret_key = secrets.token_bytes(32)
    SESSION_KEY_FILE.write_bytes(app.secret_key)
    SESSION_KEY_FILE.chmod(0o600)  # only owner can read

app.config['SESSION_COOKIE_SECURE'] = False  # set True if HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Path to the SQLite DB inside the project
DB_PATH = Path(__file__).resolve().parent.parent / "db" / "users.sqlite"


def get_db_connection():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn





@app.route("/", methods=["GET"])
def index():
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    data = request.get_json(silent=True)
    if data is None:
        data = request.form

    username = data.get("username")
    password = data.get("password")
    recaptcha_response = data.get("g-recaptcha-response")

    if not username or not password:
        if ENABLE_LOGGING:
            log_auth_attempt(username or "unknown", client_ip, False, "Missing credentials")
        return jsonify({"success": False, "error": "Invalid credentials"}), 400

    # Defense 3.2: Check if account is locked (before any other checks)
    if ENABLE_COUNTER:
        locked, remaining = is_account_locked(username)
        if locked:
            if ENABLE_LOGGING:
                log_auth_attempt(username, client_ip, False, f"Account locked ({remaining}s remaining)")
            return jsonify({"success": False, "error": f"Account locked. Try again in {remaining} seconds"}), 403

    # Defense 3.1: Apply delay EARLY to slow down all attempts (even CAPTCHA fails)
    if ENABLE_DELAY:
        if DEFENSE_MODE == "linear":
            apply_linear_delay()
        else:
            apply_progressive_delay(username)

    # Defense 3.2: Verify reCAPTCHA challenge (after delay)
    if ENABLE_CAPTCHA:
        captcha_valid, captcha_error = verify_recaptcha(recaptcha_response, client_ip)
        if not captcha_valid:
            if ENABLE_LOGGING:
                log_auth_attempt(username or "unknown", client_ip, False, f"CAPTCHA failed: {captcha_error}")
            return jsonify({"success": False, "error": captcha_error or "reCAPTCHA verification failed"}), 400

    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if row and row["password_hash"] is not None:
            try:
                password_bytes = password.encode('utf-8')
                hash_bytes = row["password_hash"].encode('utf-8') if isinstance(row["password_hash"], str) else row["password_hash"]
                if bcrypt.checkpw(password_bytes, hash_bytes):
                    # Successful login
                    if ENABLE_COUNTER:
                        reset_failed_attempts(username)
                    if ENABLE_LOGGING:
                        log_auth_attempt(username, client_ip, True, "Login successful")
                    
                    session.permanent = True
                    session["username"] = username
                    session["logged_in"] = True
                    return jsonify({"success": True, "message": "login successful"})
            except (ValueError, AttributeError):
                pass
        
        # Failed login
        if ENABLE_COUNTER:
            increment_failed_attempts(username)
        if ENABLE_LOGGING:
            log_auth_attempt(username, client_ip, False, "Invalid credentials")
        return jsonify({"success": False, "error": "Invalid credentials"}), 401
    finally:
        conn.close()


@app.route("/profile", methods=["GET"])
def profile():
    # session-based authentication
    if not session.get("logged_in"):
        return jsonify({"error": "Authentication required"}), 401
    
    username = request.args.get("username") or session.get("username")
    if not username:
        return jsonify({"error": "username parameter required"}), 400

    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT username, email FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "user not found"}), 404
        return jsonify({"username": row["username"], "email": row["email"]})
    finally:
        conn.close()


if __name__ == "__main__":
    # secured with defense mechanisms
    print("=" * 70)
    print("SECURE SERVER - Defense Mechanisms Configuration")
    print("=" * 70)
    print(f"  [3.1] Delay: {'ENABLED' if ENABLE_DELAY else 'DISABLED'} (Mode: {DEFENSE_MODE})")
    print(f"  [3.2] Counter-Limit: {'ENABLED' if ENABLE_COUNTER else 'DISABLED'} (5 attempts → 5min lockout)")
    print(f"  [3.2] reCAPTCHA: {'ENABLED' if ENABLE_CAPTCHA else 'DISABLED'}")
    print(f"  [3.3] Logging: {'ENABLED' if ENABLE_LOGGING else 'DISABLED'}")
    print("=" * 70)
    print(f"Server starting on http://127.0.0.1:5001")
    print()
    print("To customize defenses, set environment variables:")
    print("  ENABLE_DELAY=false    - Disable delay mechanism")
    print("  ENABLE_COUNTER=false  - Disable counter/lockout")
    print("  ENABLE_CAPTCHA=false  - Disable CAPTCHA verification")
    print("  ENABLE_LOGGING=false  - Disable authentication logging")
    print("  DEFENSE_MODE=linear   - Use linear delay instead of progressive")
    print("=" * 70)
    print()
    app.run(debug=True, host="127.0.0.1", port=5001)

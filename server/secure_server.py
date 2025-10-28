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
from defense.delay import apply_progressive_delay
from defense.counter import is_account_locked, increment_failed_attempts, reset_failed_attempts
from defense.logging import log_auth_attempt

app = Flask(__name__, template_folder="templates")

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
    # get real client IP (handle proxies)
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    
    # Accept JSON or form-encoded body
    data = request.get_json(silent=True)
    if data is None:
        data = request.form

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        log_auth_attempt(username or "unknown", client_ip, False, "missing credentials")
        return jsonify({"success": False, "error": "Invalid credentials"}), 400

    # Defense 3.2: check if account is locked
    locked, remaining = is_account_locked(username)
    if locked:
        log_auth_attempt(username, client_ip, False, f"account locked ({remaining}s remaining)")
        # generic error message to not leak account status
        return jsonify({"success": False, "error": "Invalid credentials"}), 401

    # Defense 3.1: apply progressive delay (exponential backoff per user)
    apply_progressive_delay(username)

    conn = get_db_connection()
    try:
        # CRITICAL: use bcrypt hashed passwords, NOT plaintext
        cur = conn.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        
        # constant-time comparison to prevent timing attacks
        if row and row["password_hash"] is not None:
            try:
                # bcrypt.checkpw is timing-attack resistant
                password_bytes = password.encode('utf-8')
                hash_bytes = row["password_hash"].encode('utf-8') if isinstance(row["password_hash"], str) else row["password_hash"]
                
                if bcrypt.checkpw(password_bytes, hash_bytes):
                    # Success - Defense 3.2: reset counter, Defense 3.3: log
                    reset_failed_attempts(username)
                    log_auth_attempt(username, client_ip, True, "login successful")
                    
                    session.permanent = True
                    session["username"] = username
                    session["logged_in"] = True
                    
                    return jsonify({"success": True, "message": "login successful"})
            except (ValueError, AttributeError):
                # invalid hash format
                pass
        
        # Failed - Defense 3.2: increment counter, Defense 3.3: log
        increment_failed_attempts(username)
        log_auth_attempt(username, client_ip, False, "invalid credentials")
        # generic error message (don't reveal if user exists)
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
    print("Starting secure server with defense mechanisms:")
    print("  - 3.1: Linear Delay (1.0s per attempt)")
    print("  - 3.2: Counter-Limit (5 attempts → 5min lockout)")
    print("  - 3.3: Logging (database + file)")
    app.run(debug=True, host="127.0.0.1", port=5001)

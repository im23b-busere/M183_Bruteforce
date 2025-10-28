"""
================================================================================
File:        vulnerable_server.py
Description: Intentionally vulnerable Flask server for testing attacks
             No defense mechanisms - for demonstration purposes only
Parameters:  Runs on http://127.0.0.1:5000 by default
Author:      Erik Buser
Date:        2025-10-28
================================================================================
"""

from flask import Flask, render_template, request, jsonify
import sqlite3
from pathlib import Path

app = Flask(__name__, template_folder="templates")

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
    # Accept JSON or form-encoded body
    data = request.get_json(silent=True)
    if data is None:
        data = request.form

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"success": False, "error": "username and password required"}), 400

    conn = get_db_connection()
    try:
        # parameterized query (still intentionally no other protections)
        cur = conn.execute("SELECT password_plain FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if row and row["password_plain"] is not None and password == row["password_plain"]:
            return jsonify({"success": True, "message": "login successful"})
        else:
            return jsonify({"success": False, "message": "invalid credentials"}), 401
    finally:
        conn.close()


@app.route("/profile", methods=["GET"])
def profile():
    username = request.args.get("username")
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
    # intentionally vulnerable: no auth, no rate limiting, debug True
    app.run(debug=True, host="127.0.0.1", port=5000)

"""
================================================================================
File:        logging.py
Description: Authentication logging defense mechanism (3.3)
             Logs all authentication attempts to database and file for monitoring
Parameters:  Logs to:
             - Database: auth_attempts table in db/users.sqlite
             - File: server_secure.log
Author:      Raiyan Mahfuz
Date:        2025-10-28
================================================================================
"""

import time
import sqlite3
import logging
from pathlib import Path
import requests

DB_PATH = Path(__file__).resolve().parent.parent / "db" / "users.sqlite"

# Formspree settings (get your form ID from https://formspree.io/)
# After creating a form, you'll get a URL like: https://formspree.io/f/YOUR_FORM_ID
FORMSPREE_FORM_ID = "https://formspree.io/f/xkgpradq"  
FORMSPREE_ENABLED = False  # Set to True once you've configured Formspree

# Email alert thresholds
EMAIL_ALERT_THRESHOLD = 3  # Send email after this many failed attempts
EMAIL_ALERT_WINDOW = 300  # Time window in seconds (5 minutes)

# setup logging to file
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('server_secure.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('secure_server')

# In-memory cache for last alert times (to avoid spam)
_last_alert_times = {}


def get_last_alert_time(username):
    """Get the last time an alert email was sent for this user."""
    return _last_alert_times.get(username)


def set_last_alert_time(username):
    """Record that an alert email was sent for this user."""
    _last_alert_times[username] = time.time()


def log_auth_attempt(username, ip_address, success, note=""):
    """Log authentication attempt to database and file. Optionally notify user by email on failed attempts.
    WARNING: Never log passwords or sensitive data!
    """
    # log to database
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row  # Enable dict-like access to rows
    try:
        conn.execute(
            "INSERT INTO auth_attempts (username, ip, timestamp, success, method, note) VALUES (?, ?, ?, ?, ?, ?)",
            (username, ip_address, int(time.time()), 1 if success else 0, "password", note)
        )
        conn.commit()

        # If failed attempt, check if we should send email alert
        if not success:
            cur = conn.execute("SELECT email FROM users WHERE username = ?", (username,))
            row = cur.fetchone()
            if row and row["email"]:
                # Check number of recent failed attempts
                threshold_time = int(time.time()) - EMAIL_ALERT_WINDOW
                cur = conn.execute(
                    "SELECT COUNT(*) as count FROM auth_attempts WHERE username = ? AND success = 0 AND timestamp > ?",
                    (username, threshold_time)
                )
                count_row = cur.fetchone()
                failed_count = count_row["count"] if count_row else 0
                
                # Send email only if threshold is reached
                if failed_count >= EMAIL_ALERT_THRESHOLD:
                    # Check if we already sent an email recently (to avoid spam)
                    last_alert_time = get_last_alert_time(username)
                    if not last_alert_time or (time.time() - last_alert_time) > EMAIL_ALERT_WINDOW:
                        send_alert_email(row["email"], username, ip_address, note, failed_count)
                        set_last_alert_time(username)
    finally:
        conn.close()

    # log to file (sanitized - never log passwords!)
    status = "SUCCESS" if success else "FAILED"
    logger.info(f"AUTH {status} - user={username}, ip={ip_address}, note={note}")


def send_alert_email(email_to, username, ip_address, note, failed_count):
    """Send an alert email to the user on failed login attempt using Formspree."""
    if not FORMSPREE_ENABLED:
        logger.info(f"Formspree disabled - would have sent alert to {email_to}")
        return
    
    # Formspree endpoint
    url = FORMSPREE_FORM_ID  # Already the full URL
    
    # Prepare email data
    data = {
        "_replyto": email_to,
        "email": email_to,
        "subject": "[BruteForce Demo] ALERT: Multiple Failed Login Attempts",
        "message": f"""
Hello {username},

SECURITY ALERT: There have been {failed_count} failed login attempts to your account in the last {EMAIL_ALERT_WINDOW // 60} minutes.

Latest attempt details:
  Username: {username}
  IP Address: {ip_address}
  Note: {note}
  Time: {time.strftime('%Y-%m-%d %H:%M:%S')}

This could indicate a brute-force attack in progress.

If this was not you, please:
1. Change your password immediately
2. Contact your administrator
3. Review your account activity

--
BruteForce Demo System
"""
    }
    
    try:
        response = requests.post(url, data=data, timeout=5)
        if response.status_code == 200:
            logger.info(f"Alert email sent to {email_to} via Formspree ({failed_count} failed attempts)")
        else:
            logger.warning(f"Formspree returned status {response.status_code}: {response.text}")
    except Exception as e:
        logger.warning(f"Failed to send alert email via Formspree to {email_to}: {e}")

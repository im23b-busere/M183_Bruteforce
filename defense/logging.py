# Defense 3.3: Logging with alerts
# This module logs authentication attempts to database and file

import time
import sqlite3
import logging
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "db" / "users.sqlite"

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


def log_auth_attempt(username, ip_address, success, note=""):
    """Log authentication attempt to database and file.
    WARNING: Never log passwords or sensitive data!
    """
    # log to database
    conn = sqlite3.connect(str(DB_PATH))
    try:
        conn.execute(
            "INSERT INTO auth_attempts (username, ip, timestamp, success, method, note) VALUES (?, ?, ?, ?, ?, ?)",
            (username, ip_address, int(time.time()), 1 if success else 0, "password", note)
        )
        conn.commit()
    finally:
        conn.close()
    
    # log to file (sanitized - never log passwords!)
    status = "SUCCESS" if success else "FAILED"
    logger.info(f"AUTH {status} - user={username}, ip={ip_address}, note={note}")

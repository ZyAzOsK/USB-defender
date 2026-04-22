"""
logger.py
---------
Event logging to text file and SQLite database.
Uses the unified db.py module for all database operations.
"""

import os
import datetime
from db import DB_FILE, LOG_FILE, compute_sha256, get_connection, _db_lock, init_db

# Ensure DB tables exist on import
init_db()


def log_event(event_type, file_path, info):
    """
    Log a filesystem event to both text log and SQLite DB.
    info dict must contain:
       tag, severity, category, action, description
       quarantine_path (optional)
    """
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    file_size = None
    sha256 = None

    try:
        if os.path.exists(file_path):
            file_size = os.path.getsize(file_path)
            if event_type.upper() in ("CREATED", "MODIFIED", "SCAN"):
                sha256 = compute_sha256(file_path)
    except Exception:
        pass

    tag = info.get("tag", "Unknown")
    severity = info.get("severity", 0)
    category = info.get("category", "Unknown")
    action = info.get("action", "None")
    description = info.get("description", "No description available")
    quarantine_path = info.get("quarantine_path", None)

    # --- Text log entry ---
    try:
        with open(LOG_FILE, "a") as f:
            f.write(
                f"[{ts}] {event_type}: {file_path} "
                f"(size={file_size}, sha256={sha256}) "
                f"→ Tag={tag}, Severity={severity}, Category={category}, "
                f"Quarantine={quarantine_path}\n"
            )
    except Exception:
        pass

    # --- Database record (thread-safe) ---
    with _db_lock:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO logs (
                timestamp, event_type, file_path, file_size, sha256,
                tag, severity, category, action, description, quarantine_path
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ts, event_type, file_path, file_size, sha256,
            tag, severity, category, action, description, quarantine_path
        ))
        conn.commit()
        conn.close()

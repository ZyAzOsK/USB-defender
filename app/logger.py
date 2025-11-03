# app/logger.py
import os
import sqlite3
import hashlib
import datetime
from pathlib import Path
from signatures import match_file

LOG_DIR = Path(__file__).resolve().parent / "logs"
LOG_FILE = LOG_DIR / "activity.log"
DB_FILE = LOG_DIR / "activity.db"

os.makedirs(LOG_DIR, exist_ok=True)

# --- DB INITIALIZATION ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_type TEXT,
            file_path TEXT,
            file_size INTEGER,
            sha256 TEXT,
            result_tag TEXT
        )
    """)
    conn.commit()
    conn.close()

# --- HASH UTILITY ---
def compute_sha256(file_path: str):
    try:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

# --- MAIN LOGGER ---
def log_event(event_type, file_path, result_tag=None):
    from signatures import match_file  # import locally to avoid circular dependency

    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    file_size = None
    sha256 = None

    try:
        if os.path.exists(file_path):
            file_size = os.path.getsize(file_path)
            if event_type in ("CREATED", "MODIFIED"):
                sha256 = compute_sha256(file_path)

                # threat Intelligence phase
                # Check file against known hashes or suspicious patterns
                is_suspicious, tag = match_file(file_path)
                if is_suspicious:
                    result_tag = tag
    except Exception:
        pass

    # write text log
    with open(LOG_FILE, "a") as f:
        f.write(f"[{ts}] {event_type}: {file_path} (size={file_size}) tag={result_tag}\n")

    # write DB record
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO logs (timestamp, event_type, file_path, file_size, sha256, result_tag) VALUES (?, ?, ?, ?, ?, ?)",
        (ts, event_type, file_path, file_size, sha256, result_tag),
    )
    conn.commit()
    conn.close()

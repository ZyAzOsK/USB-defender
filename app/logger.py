import os
import sqlite3
import hashlib
import datetime
from pathlib import Path

LOG_DIR = Path(__file__).resolve().parent / "logs"
LOG_FILE = LOG_DIR / "activity.log"
DB_FILE = Path(__file__).resolve().parent / "usb_defender.db"

os.makedirs(LOG_DIR, exist_ok=True)

# --- DB INITIALIZATION ---
def init_db():
    """Initialize the SQLite database for event logging."""
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
            tag TEXT,
            severity INTEGER,
            category TEXT,
            action TEXT,
            description TEXT,
            quarantine_path TEXT
        )
    """)
    conn.commit()
    conn.close()


# --- HASH UTILITY ---
def compute_sha256(file_path: str):
    """Compute the SHA256 hash of a file safely."""
    try:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


# --- MAIN LOGGER ---
def log_event(event_type, file_path, info):
    """
    Log a filesystem event to both text and SQLite DB.
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
            if event_type.upper() in ("CREATED", "MODIFIED"):
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
    with open(LOG_FILE, "a") as f:
        f.write(
            f"[{ts}] {event_type}: {file_path} "
            f"(size={file_size}, sha256={sha256}) "
            f"→ Tag={tag}, Severity={severity}, Category={category}, "
            f"Quarantine={quarantine_path}\n"
        )

    # --- Database record ---
    conn = sqlite3.connect(DB_FILE)
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

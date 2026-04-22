"""
db.py
-----
Single source of truth for database configuration, initialization,
and shared utilities. Replaces init_db.py and deduplicates logic
from logger.py / signatures.py.
"""

import os
import hashlib
import sqlite3
import threading
from pathlib import Path

# ==============================
# Paths
# ==============================
BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "usb_defender.db"
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "activity.log"

os.makedirs(LOG_DIR, exist_ok=True)

# ==============================
# Thread-safe DB access
# ==============================
_db_lock = threading.Lock()


def get_connection() -> sqlite3.Connection:
    """
    Return a SQLite connection with WAL journal mode
    and check_same_thread=False for multi-threaded safety.
    Callers are responsible for closing the connection.
    """
    conn = sqlite3.connect(str(DB_FILE), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init_db():
    """
    Initialize all database tables. Safe to call multiple times
    (uses CREATE TABLE IF NOT EXISTS).
    """
    with _db_lock:
        conn = get_connection()
        cur = conn.cursor()

        # --- Event logs table ---
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

        # --- Quarantine table (was missing!) ---
        cur.execute("""
            CREATE TABLE IF NOT EXISTS quarantine (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                original_path TEXT,
                quarantine_path TEXT,
                meta_path TEXT,
                tag TEXT,
                severity INTEGER,
                category TEXT,
                action TEXT,
                description TEXT
            )
        """)

        # --- Known threats reference table ---
        cur.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sha256 TEXT UNIQUE,
                tag TEXT,
                severity INTEGER,
                category TEXT,
                description TEXT
            )
        """)

        conn.commit()
        conn.close()


# ==============================
# Shared utility: SHA256
# ==============================
def compute_sha256(file_path: str) -> str | None:
    """Compute the SHA256 hash of a file safely, reading in chunks."""
    try:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

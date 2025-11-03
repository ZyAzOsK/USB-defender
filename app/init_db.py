from pathlib import Path
import sqlite3

BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "usb_defender.db"

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
        tag TEXT,
        severity INTEGER,
        category TEXT,
        action TEXT,
        description TEXT
    )
    """)

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

if __name__ == "__main__":
    init_db()

# app/quarantine.py
"""
Quarantine engine — moves, encrypts, and records malicious files.
Files are encrypted with Fernet before storage to neutralize payloads.
"""

import os
import uuid
import json
from datetime import datetime, timedelta
from cryptography.fernet import Fernet

from db import get_connection, _db_lock
from paths import get_data_dir

SUMMARY_FILE = get_data_dir() / "quarantine_summary.json"

# Fernet has no streaming API — encrypting requires the whole payload in
# memory, and the ciphertext roughly doubles it. Refuse oversized files
# rather than OOM the sidecar; they stay in place and remain flagged.
MAX_QUARANTINE_SIZE = 256 * 1024 * 1024  # 256 MB


def update_summary():
    """Rebuild quarantine_summary.json from DB."""
    with _db_lock:
        conn = get_connection()
        cur = conn.cursor()

        # --- All-time stats ---
        cur.execute("SELECT COUNT(*), SUM(severity) FROM quarantine")
        total_count, total_severity = cur.fetchone()
        total_severity = total_severity or 0

        # --- Daily stats ---
        today = datetime.now().strftime("%Y-%m-%d")
        cur.execute("SELECT COUNT(*) FROM quarantine WHERE timestamp LIKE ?", (f"{today}%",))
        daily_count = cur.fetchone()[0]

        # --- Weekly stats ---
        week_ago = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
        cur.execute("SELECT COUNT(*) FROM quarantine WHERE timestamp >= ?", (week_ago,))
        weekly_count = cur.fetchone()[0]

        # --- Top threats ---
        cur.execute("""
            SELECT tag, COUNT(*) AS hits
            FROM quarantine
            GROUP BY tag
            ORDER BY hits DESC
            LIMIT 5
        """)
        top_threats = [{"tag": t, "count": c} for t, c in cur.fetchall()]

        conn.close()

    summary = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "stats": {
            "total_quarantined": total_count or 0,
            "total_severity_score": total_severity,
            "daily_quarantined": daily_count,
            "weekly_quarantined": weekly_count,
        },
        "top_threats": top_threats,
    }

    with open(SUMMARY_FILE, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=4)


def quarantine_file(file_path, info, quarantine_dir):
    """
    Quarantine a suspicious file:
    1. Read its contents
    2. Encrypt with Fernet
    3. Write encrypted data as .qfile
    4. Delete the original
    5. Store encryption key + metadata in .meta.json
    6. Insert DB record
    7. Update summary

    Returns the path to the encrypted .qfile on success, or None on failure,
    so callers can record where the payload actually went.
    """

    try:
        try:
            file_size = os.path.getsize(file_path)
        except OSError as e:
            print(f"[quarantine][ERROR] cannot stat {file_path}: {e}")
            return None

        if file_size > MAX_QUARANTINE_SIZE:
            print(
                f"[quarantine][SKIP] {file_path} is {file_size / (1024*1024):.0f} MB, "
                f"above the {MAX_QUARANTINE_SIZE // (1024*1024)} MB limit — "
                "left in place and reported only."
            )
            return None

        os.makedirs(quarantine_dir, exist_ok=True)

        # Unique quarantine filename
        quarantine_id = str(uuid.uuid4())
        quarantine_path = os.path.join(quarantine_dir, f"{quarantine_id}.qfile")
        metadata_file = os.path.join(quarantine_dir, f"{quarantine_id}.meta.json")

        # --- Read original file contents ---
        with open(file_path, "rb") as f:
            original_data = f.read()

        # --- Generate encryption key and encrypt ---
        fernet_key = Fernet.generate_key()
        fernet = Fernet(fernet_key)
        encrypted_data = fernet.encrypt(original_data)

        # --- Write encrypted quarantine file ---
        with open(quarantine_path, "wb") as f:
            f.write(encrypted_data)

        # --- Remove the original ---
        os.remove(file_path)

        print(f"[QUARANTINED] {file_path} -> {quarantine_path} (encrypted)")

        # --- Write metadata JSON (includes encryption key) ---
        metadata = {
            "id": quarantine_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "original_path": file_path,
            "quarantine_path": quarantine_path,
            "meta_path": metadata_file,
            "encryption_key": fernet_key.decode("utf-8"),
            "tag": info.get("tag"),
            "severity": info.get("severity"),
            "category": info.get("category"),
            "action": info.get("action"),
            "description": info.get("description"),
        }

        with open(metadata_file, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=4)

        # --- Insert DB record (thread-safe) ---
        with _db_lock:
            conn = get_connection()
            cur = conn.cursor()

            cur.execute("""
                INSERT INTO quarantine (
                    timestamp, original_path, quarantine_path,
                    meta_path, tag, severity, category, action, description
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                metadata["timestamp"],
                metadata["original_path"],
                metadata["quarantine_path"],
                metadata["meta_path"],
                metadata["tag"],
                metadata["severity"],
                metadata["category"],
                metadata["action"],
                metadata["description"],
            ))

            conn.commit()
            conn.close()

        # Update summary
        update_summary()

        return quarantine_path

    except Exception as e:
        print(f"[quarantine][ERROR] {e}")
        return None

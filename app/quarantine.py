# app/quarantine.py

import os
import shutil
import uuid
import json
import sqlite3
from pathlib import Path
from datetime import datetime

DB_FILE = Path(__file__).resolve().parent / "usb_defender.db"


def quarantine_file(file_path, info, quarantine_dir):
    """
    Move suspicious file to quarantine folder + create metadata file + DB entry.
    """

    try:
        os.makedirs(quarantine_dir, exist_ok=True)

        # Unique quarantine filename
        quarantine_id = str(uuid.uuid4())
        quarantine_file = os.path.join(quarantine_dir, f"{quarantine_id}.qfile")
        metadata_file = os.path.join(quarantine_dir, f"{quarantine_id}.meta.json")

        # Move file into quarantine
        shutil.move(file_path, quarantine_file)

        print(f"[QUARANTINED] {file_path} -> {quarantine_file}")

        # Write metadata json
        metadata = {
            "id": quarantine_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "original_path": file_path,
            "quarantine_path": quarantine_file,
            "tag": info.get("tag"),
            "severity": info.get("severity"),
            "category": info.get("category"),
            "action": info.get("action"),
            "description": info.get("description"),
        }

        with open(metadata_file, "w") as f:
            json.dump(metadata, f, indent=4)

        # Insert DB record
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO quarantine (
                timestamp, original_path, quarantine_path,
                meta_path, tag, severity, category, action, description
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            metadata["timestamp"],
            file_path,
            quarantine_file,     # <-- FIXED HERE
            metadata_file,
            info.get("tag"),
            info.get("severity"),
            info.get("category"),
            info.get("action"),
            info.get("description"),
        ))

        conn.commit()
        conn.close()

        return True

    except Exception as e:
        print(f"[quarantine][ERROR] {e}")
        return False

# app/quarantine.py

import os
import shutil
import uuid
import json
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta

DB_FILE = Path(__file__).resolve().parent / "usb_defender.db"
SUMMARY_FILE = Path(__file__).resolve().parent / "quarantine_summary.json"


def update_summary():
    """Rebuild quarantine_summary.json from DB."""

    conn = sqlite3.connect(DB_FILE)
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

    with open(SUMMARY_FILE, "w") as f:
        json.dump(summary, f, indent=4)


def quarantine_file(file_path, info, quarantine_dir):
    """
    Move suspicious file to quarantine folder + create metadata + DB entry +
    update quarantine_summary.json.
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
            "meta_path": metadata_file,
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

        # === Phase 8: Update summary ===
        update_summary()

        return True

    except Exception as e:
        print(f"[quarantine][ERROR] {e}")
        return False

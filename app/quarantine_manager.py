#!/usr/bin/env python3
import sqlite3
from tabulate import tabulate
import argparse
import os
import shutil
from pathlib import Path

DB_FILE = Path(__file__).resolve().parent / "usb_defender.db"


# ---------------------------------------
# 🔍 LIST QUARANTINED ITEMS
# ---------------------------------------
def list_quarantined():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    cur.execute("""
        SELECT id, timestamp, original_path, quarantine_path,
               meta_path, tag, severity, category
        FROM quarantine
        ORDER BY id DESC
    """)

    rows = cur.fetchall()
    conn.close()
    return rows


# ---------------------------------------
# ♻ RESTORE QUARANTINED ITEM
# ---------------------------------------
def restore_quarantined(entry_id):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    cur.execute("""
        SELECT original_path, quarantine_path, meta_path
        FROM quarantine WHERE id = ?
    """, (entry_id,))
    
    row = cur.fetchone()
    if not row:
        print("❌ No such quarantine entry.")
        return

    original_path, quarantine_path, meta_path = row

    try:
        # Restore file to original path
        shutil.move(quarantine_path, original_path)
        print(f"✅ Restored: {original_path}")

        # Cleanup metadata file
        if meta_path and os.path.exists(meta_path):
            os.remove(meta_path)

        # Remove DB entry
        cur.execute("DELETE FROM quarantine WHERE id = ?", (entry_id,))
        conn.commit()

    except Exception as e:
        print(f"❌ Restore failed: {e}")

    conn.close()


# ---------------------------------------
# 🗑 DELETE QUARANTINED ITEM PERMANENTLY
# ---------------------------------------
def delete_quarantined(entry_id):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    cur.execute("""
        SELECT quarantine_path, meta_path
        FROM quarantine WHERE id = ?
    """, (entry_id,))
    
    row = cur.fetchone()
    if not row:
        print("❌ No such quarantine entry.")
        return

    quarantine_path, meta_path = row

    # Delete files
    for f in [quarantine_path, meta_path]:
        if f and os.path.exists(f):
            try:
                os.remove(f)
            except:
                pass

    # Remove DB entry
    cur.execute("DELETE FROM quarantine WHERE id = ?", (entry_id,))
    conn.commit()
    conn.close()

    print("🗑 Deleted quarantined file + metadata + DB entry.")


# ---------------------------------------
# 🚀 MAIN CLI
# ---------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Quarantine Manager")

    parser.add_argument("--list", action="store_true", help="List quarantined items")
    parser.add_argument("--restore", type=int, help="Restore quarantined item by ID")
    parser.add_argument("--delete", type=int, help="Delete quarantined item by ID")

    args = parser.parse_args()

    # List all
    if args.list:
        rows = list_quarantined()
        if not rows:
            print("No quarantined items.")
            return

        print(tabulate(
            rows,
            headers=[
                "ID", "Timestamp", "Original Path", "Quarantine Path",
                "Metadata", "Tag", "Severity", "Category"
            ],
            tablefmt="fancy_grid"
        ))
        return

    # Restore
    if args.restore:
        restore_quarantined(args.restore)
        return

    # Delete
    if args.delete:
        delete_quarantined(args.delete)
        return

    print("Use --list / --restore <id> / --delete <id>")


if __name__ == "__main__":
    main()

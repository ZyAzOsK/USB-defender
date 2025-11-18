#!/usr/bin/env python3
import sqlite3
from tabulate import tabulate
import argparse
import json
import os
import shutil
from pathlib import Path

DB_FILE = Path(__file__).resolve().parent / "usb_defender.db"
SUMMARY_FILE = Path(__file__).resolve().parent / "quarantine_summary.json"


# -----------------------------------
# LIST QUARANTINED ITEMS
# -----------------------------------
def list_quarantined():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    cur.execute("""
        SELECT id, timestamp, original_path, quarantine_path, meta_path,
               tag, severity, category
        FROM quarantine ORDER BY id DESC
    """)

    rows = cur.fetchall()
    conn.close()
    return rows


# -----------------------------------
# RESTORE
# -----------------------------------
def restore_quarantined(entry_id):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    cur.execute("SELECT original_path, quarantine_path FROM quarantine WHERE id = ?", (entry_id,))
    row = cur.fetchone()
    if not row:
        print("❌ No such quarantine entry.")
        return

    original_path, quarantine_path = row

    try:
        shutil.move(quarantine_path, original_path)
        print(f"✅ Restored file to: {original_path}")
    except Exception as e:
        print(f"❌ Restore failed: {e}")
        return

    conn.close()


# -----------------------------------
# DELETE (file + metadata + DB record)
# -----------------------------------
def delete_quarantined(entry_id):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    cur.execute("SELECT quarantine_path, meta_path FROM quarantine WHERE id = ?", (entry_id,))
    row = cur.fetchone()
    if not row:
        print("❌ No such quarantine entry.")
        return

    quarantine_path, meta_path = row

    # Remove files safely
    for path in [quarantine_path, meta_path]:
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except Exception:
                pass

    # Remove DB record
    cur.execute("DELETE FROM quarantine WHERE id = ?", (entry_id,))
    conn.commit()
    conn.close()

    print("🗑️ Deleted quarantine entry + related files.")


# -----------------------------------
# SUMMARY VIEW (from JSON)
# -----------------------------------
def show_summary():
    if not SUMMARY_FILE.exists():
        print("⚠️ No summary file found. Quarantine something first.")
        return

    with open(SUMMARY_FILE, "r") as f:
        summary = json.load(f)

    print("\n📊 QUARANTINE SUMMARY\n")

    stats = summary["stats"]
    top = summary["top_threats"]

    print(tabulate(
        [
            ["Total Quarantined", stats["total_quarantined"]],
            ["Total Severity Score", stats["total_severity_score"]],
            ["Quarantined Today", stats["daily_quarantined"]],
            ["Quarantined This Week", stats["weekly_quarantined"]],
            ["Generated At", summary["generated_at"]],
        ],
        tablefmt="fancy_grid"
    ))

    # ---- FIXED TOP THREATS TABLE ----
    if top:
        print("\n🔥 TOP THREATS\n")

        # Convert dicts → list-of-lists
        top_rows = [[item["tag"], item["count"]] for item in top]

        print(tabulate(
            top_rows,
            headers=["Tag", "Count"],
            tablefmt="fancy_grid"
        ))
    else:
        print("\n(No threats recorded yet)\n")



# -----------------------------------
# MAIN CLI
# -----------------------------------
def main():
    parser = argparse.ArgumentParser(description="USB Defender Quarantine Manager")
    parser.add_argument("--list", action="store_true", help="Show all quarantined items")
    parser.add_argument("--restore", type=int, help="Restore quarantined item by ID")
    parser.add_argument("--delete", type=int, help="Delete quarantined item by ID")
    parser.add_argument("--summary", action="store_true", help="Show quarantine summary")

    args = parser.parse_args()

    if args.summary:
        show_summary()
        return

    if args.list:
        rows = list_quarantined()
        if not rows:
            print("No quarantined items.")
            return

        print(tabulate(
            rows,
            headers=[
                "ID", "Timestamp", "Original Path",
                "Quarantine File", "Metadata File",
                "Tag", "Severity", "Category"
            ],
            tablefmt="fancy_grid"
        ))
        return

    if args.restore:
        restore_quarantined(args.restore)
        return

    if args.delete:
        delete_quarantined(args.delete)
        return

    # If no args
    parser.print_help()


if __name__ == "__main__":
    main()

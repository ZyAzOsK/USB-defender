#!/usr/bin/env python3
"""
quarantine_manager.py
---------------------
CLI tool to list, restore, delete, and summarize quarantined files.
Supports Fernet decryption on restore.
"""

from tabulate import tabulate
import argparse
import json
import os
from cryptography.fernet import Fernet

from db import get_connection, _db_lock
from paths import get_data_dir

SUMMARY_FILE = get_data_dir() / "quarantine_summary.json"


# -----------------------------------
# LIST QUARANTINED ITEMS
# -----------------------------------
def list_quarantined():
    with _db_lock:
        conn = get_connection()
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
# RESTORE (with decryption)
# -----------------------------------
def restore_quarantined(entry_id):
    with _db_lock:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute(
            "SELECT original_path, quarantine_path, meta_path FROM quarantine WHERE id = ?",
            (entry_id,)
        )
        row = cur.fetchone()
        if not row:
            print("❌ No such quarantine entry.")
            conn.close()
            return

        original_path, quarantine_path, meta_path = row

        # --- Read encryption key from metadata ---
        try:
            with open(meta_path, "r") as f:
                metadata = json.load(f)
            encryption_key = metadata.get("encryption_key")
        except Exception as e:
            print(f"❌ Failed to read metadata: {e}")
            conn.close()
            return

        # --- Decrypt the quarantined file ---
        try:
            with open(quarantine_path, "rb") as f:
                encrypted_data = f.read()

            if encryption_key:
                fernet = Fernet(encryption_key.encode("utf-8"))
                decrypted_data = fernet.decrypt(encrypted_data)
            else:
                # Legacy: unencrypted quarantine files
                decrypted_data = encrypted_data

            # --- Ensure parent directory exists ---
            os.makedirs(os.path.dirname(original_path), exist_ok=True)

            # --- Write restored file ---
            with open(original_path, "wb") as f:
                f.write(decrypted_data)

            # --- Clean up quarantine files ---
            os.remove(quarantine_path)
            if meta_path and os.path.exists(meta_path):
                os.remove(meta_path)

            print(f"✅ Restored file to: {original_path}")

        except Exception as e:
            print(f"❌ Restore failed: {e}")
            conn.close()
            return

        # --- Delete DB record (fix: was missing before!) ---
        cur.execute("DELETE FROM quarantine WHERE id = ?", (entry_id,))
        conn.commit()
        conn.close()

    print("🗄️ Quarantine record removed from database.")


# -----------------------------------
# DELETE (file + metadata + DB record)
# -----------------------------------
def delete_quarantined(entry_id):
    with _db_lock:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute("SELECT quarantine_path, meta_path FROM quarantine WHERE id = ?", (entry_id,))
        row = cur.fetchone()
        if not row:
            print("❌ No such quarantine entry.")
            conn.close()
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

    if top:
        print("\n🔥 TOP THREATS\n")
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

    parser.print_help()


if __name__ == "__main__":
    main()

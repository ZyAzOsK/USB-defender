#!/usr/bin/env python3
"""
reporter.py
-----------
CLI log viewer and CSV exporter.
Reads from the unified SQLite database.
"""

from tabulate import tabulate
import argparse
import csv
from db import get_connection, _db_lock


# -------------------------
# FETCH NORMAL LOG ENTRIES
# -------------------------
def fetch_logs(event=None, start=None, end=None, limit=50):
    with _db_lock:
        conn = get_connection()
        cur = conn.cursor()

        query = """
            SELECT timestamp, event_type, file_path, file_size, sha256,
                   tag, severity, category, action, description, quarantine_path
            FROM logs
            WHERE 1=1
        """
        params = []

        if event:
            query += " AND event_type = ?"
            params.append(event.upper())

        if start:
            query += " AND timestamp >= ?"
            params.append(start)

        if end:
            query += " AND timestamp <= ?"
            params.append(end)

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        cur.execute(query, params)
        rows = cur.fetchall()
        conn.close()
    return rows


# -------------------------
# EXPORT LOGS
# -------------------------
def export_csv(rows, filename="usb_activity_export.csv"):
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Timestamp", "Event", "File Path", "Size", "SHA256",
            "Tag", "Severity", "Category", "Action", "Description", "Quarantine Path"
        ])
        writer.writerows(rows)

    print(f"\nExported logs to {filename}")


# -------------------------
# MAIN CLI
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="USB Activity Log Reporter")

    parser.add_argument("--event", help="Filter by event type (CREATED, MODIFIED, DELETED)")
    parser.add_argument("--from", dest="start", help="Start date (YYYY-MM-DD)")
    parser.add_argument("--to", dest="end", help="End date (YYYY-MM-DD)")
    parser.add_argument("--limit", type=int, default=50, help="Number of entries to show")
    parser.add_argument("--export", action="store_true", help="Export results to CSV")

    args = parser.parse_args()

    rows = fetch_logs(args.event, args.start, args.end, args.limit)

    if not rows:
        print("No matching log entries found.")
        return

    print("\nRecent USB Activity Logs:\n")
    print(tabulate(rows, headers=[
        "Timestamp", "Event", "File Path", "Size", "SHA256",
        "Tag", "Severity", "Category", "Action", "Description", "Quarantine"
    ], tablefmt="fancy_grid"))

    if args.export:
        export_csv(rows)


if __name__ == "__main__":
    main()

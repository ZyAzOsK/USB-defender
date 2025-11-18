#!/usr/bin/env python3
import sqlite3
from tabulate import tabulate
import argparse
import csv
from pathlib import Path

# Correct unified database file
LOG_DB = Path(__file__).resolve().parent / "usb_defender.db"

def fetch_logs(event_type=None, start_date=None, end_date=None, limit=50):
    conn = sqlite3.connect(LOG_DB)
    cur = conn.cursor()

    # Query matches the actual DB schema:
    query = """
        SELECT 
            timestamp, event_type, file_path, file_size, sha256,
            tag, severity, category, action, description
        FROM logs
        WHERE 1=1
    """
    params = []

    if event_type:
        query += " AND event_type = ?"
        params.append(event_type.upper())

    if start_date:
        query += " AND timestamp >= ?"
        params.append(start_date)

    if end_date:
        query += " AND timestamp <= ?"
        params.append(end_date)

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()

    return rows


def export_csv(rows, filename="usb_activity_export.csv"):
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        # Updated headers to match actual schema
        writer.writerow([
            "Timestamp", "Event", "File Path", "Size", "SHA256",
            "Tag", "Severity", "Category", "Action", "Description"
        ])
        writer.writerows(rows)
    print(f"\nExported logs to {filename}")


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
        print("\nNo matching log entries found.")
        return

    print("\nRecent USB Activity Logs:\n")
    print(tabulate(
        rows,
        headers=[
            "Timestamp", "Event", "File Path", "Size", "SHA256",
            "Tag", "Severity", "Category", "Action", "Description"
        ],
        tablefmt="fancy_grid"
    ))

    if args.export:
        export_csv(rows)


if __name__ == "__main__":
    main()

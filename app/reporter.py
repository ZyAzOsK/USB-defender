# **USAGE**
# View the latest 20 log entries
# python app/reporter.py --limit 20

# View only created files
# python app/reporter.py --event CREATED

# Filter by date range
# python app/reporter.py --from 2025-10-30 --to 2025-10-31

# Export logs to CSV for external analysis
# python app/reporter.py --export

#!/usr/bin/env python3
import sqlite3
from tabulate import tabulate
import argparse
import datetime
import csv
from pathlib import Path

LOG_DB = Path(__file__).resolve().parent / "logs" / "activity.db"

def fetch_logs(event_type=None, start_date=None, end_date=None, limit=50):
    conn = sqlite3.connect(LOG_DB)
    cur = conn.cursor()
    
    query = "SELECT timestamp, event_type, file_path, file_size, sha256, result_tag FROM logs WHERE 1=1"
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
        writer.writerow(["Timestamp", "Event", "File Path", "Size", "SHA256", "Result Tag"])
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
        print("No matching log entries found.")
        return

    print("\nRecent USB Activity Logs:\n")
    print(tabulate(rows, headers=["Timestamp", "Event", "File Path", "Size", "SHA256", "Tag"], tablefmt="fancy_grid"))

    if args.export:
        export_csv(rows)

if __name__ == "__main__":
    main()




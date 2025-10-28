import os
import csv
import time
from datetime import datetime

# File types we consider suspicious
SUSPICIOUS_EXTENSIONS = ['.exe', '.bat', '.vbs', '.scr', '.dll']
SUSPICIOUS_NAMES = ['autorun.inf']

def is_hidden(filepath):
    """Check if a file or directory is hidden (Linux/Unix logic)."""
    return os.path.basename(filepath).startswith('.')

def scan_usb(usb_path, log_path):
    """
    Recursively scan the USB directory for suspicious files.
    Log details (path, type, timestamp) to CSV.
    """
    log_file = os.path.join(log_path, 'scan_log.csv')

    # Create logs folder if missing
    os.makedirs(log_path, exist_ok=True)

    # Initialize log file
    if not os.path.exists(log_file):
        with open(log_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Timestamp", "File Path", "Type", "Reason"])

    suspicious_count = 0
    scanned_count = 0

    for root, dirs, files in os.walk(usb_path):
        for name in files:
            scanned_count += 1
            filepath = os.path.join(root, name)
            ext = os.path.splitext(name)[1].lower()

            reason = None
            if ext in SUSPICIOUS_EXTENSIONS:
                reason = f"Executable file ({ext})"
            elif name.lower() in SUSPICIOUS_NAMES:
                reason = "Autorun file"
            elif is_hidden(name):
                reason = "Hidden file"

            if reason:
                suspicious_count += 1
                with open(log_file, 'a', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow([
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        filepath,
                        ext if ext else 'N/A',
                        reason
                    ])

    print(f"Scan complete: {scanned_count} files scanned, {suspicious_count} suspicious found.")
    print(f"Logs saved at: {log_file}")

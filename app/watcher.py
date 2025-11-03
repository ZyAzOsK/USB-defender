import time
import os
import csv
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime
from logger import log_event
from detector import detect_threat
from threat_intel import enrich_tag 


class USBEventHandler(FileSystemEventHandler):
    def __init__(self, usb_path, log_path):
        super().__init__()
        self.usb_path = usb_path
        self.log_path = log_path
        self.log_file = os.path.join(log_path, "activity_log.csv")
        os.makedirs(log_path, exist_ok=True)

        # Create CSV header if file doesn’t exist
        if not os.path.exists(self.log_file):
            with open(self.log_file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "Timestamp",
                    "Event Type",
                    "File Path",
                    "Tag",
                    "Severity",
                    "Category",
                    "Action",
                    "Description"
                ])

    def log_event(self, event_type, file_path):
        """Logs file system events (create/modify/delete) with metadata + threat intelligence."""

        findings = []

        # Only scan file content on creation or modification
        if event_type.lower() in ("created", "modified"):
            findings = detect_threat(file_path)

        if findings:
            # Enrich each finding with threat intelligence
            enriched_findings = [enrich_tag(f["tag"]) for f in findings]
        else:
            enriched_findings = [{"tag": "Clean", "severity": 0, "category": "None",
                                  "action": "No action needed", "description": "No threat detected."}]

        # Log all enriched findings
        for info in enriched_findings:
            log_event(event_type, file_path, info)
            print(f"{event_type.upper()}: {file_path} → {info['tag']} (Severity: {info['severity']})")

    def on_created(self, event):
        if not event.is_directory:
            self.log_event("Created", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.log_event("Deleted", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.log_event("Modified", event.src_path)

    def on_moved(self, event):
        if event.is_directory:
            return
        from_path = event.src_path
        to_path = event.dest_path
        print(f"MOVED: {from_path} → {to_path}")
        # Treat as a metadata event; no content scan
        log_event("MOVED", f"{from_path} → {to_path}", {
            "tag": "File Moved",
            "severity": 0,
            "category": "File System",
            "action": "No action",
            "description": "File was moved or renamed."
        })


def start_monitoring(usb_path, log_path):
    """Start real-time monitoring of the USB drive."""
    event_handler = USBEventHandler(usb_path, log_path)
    observer = Observer()
    observer.schedule(event_handler, usb_path, recursive=True)
    observer.start()

    print(f"Real-time monitoring started on: {usb_path}")
    print("Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("Monitoring stopped by user.")
    observer.join()

import time
import os
import csv
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime
from logger import log_event
from detector import detect_threat
from threat_intel import enrich_tag
from quarantine import quarantine_file   # <-- NEW


class USBEventHandler(FileSystemEventHandler):
    def __init__(self, usb_path, log_path):
        super().__init__()
        self.usb_path = usb_path
        self.log_path = log_path

        # === Phase 7.1: Create quarantine folder inside USB ===
        self.quarantine_dir = os.path.join(usb_path, "quarantine")
        os.makedirs(self.quarantine_dir, exist_ok=True)

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

    # ============================================================
    # Helper: ignore noise from /quarantine/ folder completely
    # ============================================================
    def _is_in_quarantine(self, path):
        return self.quarantine_dir in os.path.abspath(path)

    def log_event(self, event_type, file_path):
        """Logs file system events with threat intelligence & auto-quarantine."""

        findings = []

        # Skip scanning inside quarantine folder
        if self._is_in_quarantine(file_path):
            return

        # Scan only new or modified files
        if event_type.lower() in ("created", "modified"):
            findings = detect_threat(file_path)

        # Threat intel enrichment
        if findings:
            enriched_findings = [enrich_tag(f["tag"]) for f in findings]
        else:
            enriched_findings = [{
                "tag": "Clean",
                "severity": 0,
                "category": "None",
                "action": "No action needed",
                "description": "No threat detected."
            }]

        # === Phase 7.3: Auto-quarantine logic ===
        for info in enriched_findings:

            if info["severity"] >= 8:   # High severity
                quarantined = quarantine_file(file_path, info, self.quarantine_dir)

                if quarantined:
                    info["tag"] = info["tag"] + " (QUARANTINED)"
                else:
                    info["tag"] = info["tag"] + " (QUARANTINE FAILED)"

            log_event(event_type, file_path, info)
            print(f"{event_type.upper()}: {file_path} → {info['tag']} (Severity: {info['severity']})")

    # =====================
    # Watchdog event hooks
    # =====================
    def on_created(self, event):
        if event.is_directory:
            return
        if self._is_in_quarantine(event.src_path):
            return
        self.log_event("Created", event.src_path)

    def on_deleted(self, event):
        if event.is_directory:
            return
        if self._is_in_quarantine(event.src_path):
            return
        self.log_event("Deleted", event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        if self._is_in_quarantine(event.src_path):
            return
        self.log_event("Modified", event.src_path)

    def on_moved(self, event):
        if event.is_directory:
            return
        if self._is_in_quarantine(event.src_path) or self._is_in_quarantine(event.dest_path):
            return

        from_path = event.src_path
        to_path = event.dest_path

        print(f"MOVED: {from_path} → {to_path}")

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

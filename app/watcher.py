"""
watcher.py
----------
Real-time filesystem monitoring using watchdog.
Features:
- Event debouncing (0.5s per file)
- Auto-quarantine for severity >= 8
- Skip quarantine directory noise
"""

import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from logger import log_event
from detector import detect_threat
from quarantine import quarantine_file
from signatures import should_skip_path


# Debounce window in seconds
DEBOUNCE_SECONDS = 0.5

# Cap on the debounce tracker. A long-running monitor over a large drive
# would otherwise retain one dict entry per file path seen, forever.
MAX_DEBOUNCE_ENTRIES = 4096

# Kept identical to scanner.QUARANTINE_SEVERITY_THRESHOLD.
QUARANTINE_SEVERITY_THRESHOLD = 8


class USBEventHandler(FileSystemEventHandler):
    def __init__(self, usb_path, log_path):
        super().__init__()
        self.usb_path = usb_path
        self.log_path = log_path

        # Create quarantine folder inside USB
        self.quarantine_dir = os.path.join(usb_path, "quarantine")
        os.makedirs(self.quarantine_dir, exist_ok=True)

        os.makedirs(log_path, exist_ok=True)

        # Debounce tracker: {file_path: last_event_timestamp}
        self._last_event = {}

    # ============================================================
    # Helper: ignore noise from /quarantine/ folder
    # ============================================================
    def _is_in_quarantine(self, path):
        abs_path = os.path.abspath(path)
        quarantine_abs = os.path.abspath(self.quarantine_dir)
        return abs_path.startswith(quarantine_abs)

    def _should_debounce(self, file_path):
        """Return True if this event should be skipped (too soon after last)."""
        now = time.time()
        last = self._last_event.get(file_path, 0)
        if now - last < DEBOUNCE_SECONDS:
            return True

        # Evict entries that can no longer debounce anything before growing.
        if len(self._last_event) >= MAX_DEBOUNCE_ENTRIES:
            cutoff = now - DEBOUNCE_SECONDS
            self._last_event = {
                path: ts for path, ts in self._last_event.items() if ts > cutoff
            }

        self._last_event[file_path] = now
        return False

    def handle_event(self, event_type, file_path):
        """Process file system events with threat detection & auto-quarantine."""

        # Skip quarantine folder
        if self._is_in_quarantine(file_path):
            return

        # Skip developer/system noise (node_modules, .git, media files) so the
        # live feed stays readable and matches what the scanner would report.
        if should_skip_path(file_path):
            return

        # Debounce rapid duplicate events
        if self._should_debounce(file_path):
            return

        findings = []

        # Scan only new or modified files
        if event_type.lower() in ("created", "modified"):
            findings = detect_threat(file_path)

        # Build enriched findings
        if findings:
            enriched_findings = findings  # Already enriched by detector.py
        else:
            enriched_findings = [{
                "tag": "Clean",
                "severity": 0,
                "category": "None",
                "action": "No action needed",
                "description": "No threat detected."
            }]

        # Auto-quarantine high severity threats
        has_quarantined = False
        for info in enriched_findings:
            if info["severity"] >= QUARANTINE_SEVERITY_THRESHOLD:
                if not has_quarantined:
                    quarantine_path = quarantine_file(file_path, info, self.quarantine_dir)
                    if quarantine_path:
                        info["tag"] = info["tag"] + " (QUARANTINED)"
                        info["quarantine_path"] = quarantine_path
                        has_quarantined = True
                    else:
                        info["tag"] = info["tag"] + " (QUARANTINE FAILED)"
                else:
                    info["tag"] = info["tag"] + " (QUARANTINED ALREADY)"

            log_event(event_type, file_path, info)
            print(f"{event_type.upper()}: {file_path} → {info['tag']} (Severity: {info['severity']})")

    # =====================
    # Watchdog event hooks
    # =====================
    def on_created(self, event):
        if event.is_directory:
            return
        self.handle_event("Created", event.src_path)

    def on_deleted(self, event):
        if event.is_directory:
            return
        if self._is_in_quarantine(event.src_path):
            return
        self.handle_event("Deleted", event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        self.handle_event("Modified", event.src_path)

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

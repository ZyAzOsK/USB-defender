import time
import os
import csv
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime
from logger import log_event
from detector import detect_threat

class USBEventHandler(FileSystemEventHandler):
    def __init__(self, usb_path, log_path):
        super().__init__()
        self.usb_path = usb_path
        self.log_path = log_path
        self.log_file = os.path.join(log_path, 'activity_log.csv')
        os.makedirs(log_path, exist_ok=True)

        # Create header if file doesn’t exist
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "Event Type", "File Path"])

    def log_event(self, event_type, file_path):
        """Logs file system events (create/modify/delete) with metadata + threat tag."""
        result_tag = None

        # Only scan file content on creation or modification
        if event_type.lower() in ("created", "modified"):
            result_tag = detect_threat(file_path)

        # Use centralized logger
        log_event(event_type, file_path, result_tag)
        print(f"{event_type.upper()}: {file_path} | Tag: {result_tag or 'Clean'}")


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
        log_event("MOVED", f"{from_path} → {to_path}")

def start_monitoring(usb_path, log_path):
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

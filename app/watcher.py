import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime
import csv

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
        with open(self.log_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                event_type,
                file_path
            ])
        print(f"{event_type.upper()}: {file_path}")

    def on_created(self, event):
        if not event.is_directory:
            self.log_event("Created", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.log_event("Deleted", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.log_event("Modified", event.src_path)

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

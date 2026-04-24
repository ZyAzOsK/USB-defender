"""
usb_detector.py
---------------
Cross-platform USB insertion detection.

- Linux:  pyudev (udev monitoring)
- Windows: WMI Win32_VolumeChangeEvent
- macOS:  Polling /Volumes/ for new mounts

Fires a callback with the mount path whenever a USB drive is inserted.
"""

import os
import sys
import time
import platform
import threading
from pathlib import Path


class USBDetector:
    """
    Cross-platform USB drive insertion detector.

    Usage:
        def on_usb(mount_path):
            print(f"USB detected at: {mount_path}")

        detector = USBDetector(on_insert=on_usb)
        detector.start()   # non-blocking, runs in background thread
        detector.stop()    # graceful shutdown
    """

    def __init__(self, on_insert=None, on_remove=None):
        """
        Args:
            on_insert: Callable(str) — called with mount path when USB is inserted
            on_remove: Callable(str) — called with mount path when USB is removed
        """
        self.on_insert = on_insert or (lambda path: None)
        self.on_remove = on_remove or (lambda path: None)
        self._stop_event = threading.Event()
        self._thread = None
        self._system = platform.system()  # "Linux", "Windows", "Darwin"

    @property
    def running(self):
        return self._thread is not None and self._thread.is_alive()

    def start(self):
        """Start listening for USB events in a background thread."""
        if self.running:
            return

        self._stop_event.clear()

        if self._system == "Linux":
            target = self._linux_monitor
        elif self._system == "Windows":
            target = self._windows_monitor
        elif self._system == "Darwin":
            target = self._macos_monitor
        else:
            raise OSError(f"Unsupported platform: {self._system}")

        self._thread = threading.Thread(target=target, daemon=True)
        self._thread.start()

    def stop(self):
        """Signal the monitor to stop."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None

    # ──────────────────────────────────────────────
    # Linux: pyudev-based udev monitoring
    # ──────────────────────────────────────────────
    def _linux_monitor(self):
        """Monitor USB events via pyudev (udev subsystem)."""
        try:
            import pyudev
        except ImportError:
            print("[usb_detector] pyudev not installed, falling back to polling")
            self._linux_poll_fallback()
            return

        context = pyudev.Context()
        monitor = pyudev.Monitor.from_netlink(context)
        monitor.filter_by(subsystem='block', device_type='partition')

        # Non-blocking poll loop
        monitor.start()

        while not self._stop_event.is_set():
            device = monitor.poll(timeout=1)
            if device is None:
                continue

            action = device.action  # 'add', 'remove', 'change'
            dev_node = device.device_node  # e.g., /dev/sdb1

            if action == 'add':
                # Wait for mount to appear
                mount_path = self._wait_for_linux_mount(dev_node, timeout=8)
                if mount_path:
                    self.on_insert(mount_path)

            elif action == 'remove':
                # Device removed — we can report the dev_node
                self.on_remove(dev_node or "unknown")

    def _wait_for_linux_mount(self, dev_node, timeout=8):
        """
        After a partition 'add' event, wait for it to be mounted.
        Returns the mount path or None if it never appeared.
        """
        start = time.time()
        while time.time() - start < timeout:
            if self._stop_event.is_set():
                return None

            # Parse /proc/mounts for the device
            try:
                with open("/proc/mounts", "r") as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 2 and parts[0] == dev_node:
                            mount_path = parts[1]
                            # Unescape octal sequences like \040 for spaces
                            mount_path = mount_path.encode('raw_unicode_escape').decode('unicode_escape')
                            return mount_path
            except OSError:
                pass

            time.sleep(0.5)

        return None

    def _linux_poll_fallback(self):
        """Fallback: poll /run/media/ and /media/ for new mounts."""
        known_mounts = self._get_linux_mounts()

        while not self._stop_event.is_set():
            time.sleep(2)
            current = self._get_linux_mounts()

            # New mounts
            for m in current - known_mounts:
                self.on_insert(m)

            # Removed mounts
            for m in known_mounts - current:
                self.on_remove(m)

            known_mounts = current

    def _get_linux_mounts(self):
        """Get set of current USB mount paths on Linux."""
        mounts = set()
        user = os.environ.get("USER", "")

        search_dirs = [
            f"/run/media/{user}",
            f"/media/{user}",
            "/media",
        ]

        for base in search_dirs:
            if os.path.isdir(base):
                try:
                    for entry in os.listdir(base):
                        full = os.path.join(base, entry)
                        if os.path.ismount(full):
                            mounts.add(full)
                except PermissionError:
                    pass

        return mounts

    # ──────────────────────────────────────────────
    # Windows: WMI volume change events
    # ──────────────────────────────────────────────
    def _windows_monitor(self):
        """Monitor USB events via WMI on Windows."""
        try:
            import wmi
        except ImportError:
            print("[usb_detector] wmi not installed, falling back to polling")
            self._windows_poll_fallback()
            return

        c = wmi.WMI()

        # Watch for volume change events
        watcher = c.Win32_VolumeChangeEvent.watch_for(
            EventType=2  # 2 = Device Arrival
        )

        while not self._stop_event.is_set():
            try:
                event = watcher(timeout_ms=1000)
                if event:
                    drive = event.DriveName  # e.g., "E:"
                    mount_path = drive + "\\"
                    if os.path.exists(mount_path):
                        self.on_insert(mount_path)
            except Exception:
                # WMI timeout — normal, just keep polling
                pass

    def _windows_poll_fallback(self):
        """Fallback: poll Windows drive letters for new removable drives."""
        known = self._get_windows_removable_drives()

        while not self._stop_event.is_set():
            time.sleep(2)
            current = self._get_windows_removable_drives()

            for d in current - known:
                self.on_insert(d)
            for d in known - current:
                self.on_remove(d)

            known = current

    def _get_windows_removable_drives(self):
        """Get set of removable drive paths on Windows."""
        drives = set()
        try:
            import ctypes
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                if bitmask & 1:
                    path = f"{letter}:\\"
                    drive_type = ctypes.windll.kernel32.GetDriveTypeW(path)
                    if drive_type == 2:  # DRIVE_REMOVABLE
                        drives.add(path)
                bitmask >>= 1
        except Exception:
            pass
        return drives

    # ──────────────────────────────────────────────
    # macOS: Poll /Volumes/ for new mounts
    # ──────────────────────────────────────────────
    def _macos_monitor(self):
        """Monitor USB events on macOS by polling /Volumes/."""
        known = self._get_macos_volumes()

        while not self._stop_event.is_set():
            time.sleep(2)
            current = self._get_macos_volumes()

            for v in current - known:
                self.on_insert(v)
            for v in known - current:
                self.on_remove(v)

            known = current

    def _get_macos_volumes(self):
        """Get set of mounted volumes on macOS (excluding system)."""
        volumes = set()
        volumes_dir = "/Volumes"

        if os.path.isdir(volumes_dir):
            try:
                for entry in os.listdir(volumes_dir):
                    full = os.path.join(volumes_dir, entry)
                    # Skip "Macintosh HD" and similar system volumes
                    if entry not in ("Macintosh HD", "Macintosh HD - Data"):
                        if os.path.ismount(full):
                            volumes.add(full)
            except PermissionError:
                pass

        return volumes


# ──────────────────────────────────────────────
# Standalone test
# ──────────────────────────────────────────────
if __name__ == "__main__":
    def on_insert(path):
        print(f"🔌 USB INSERTED: {path}")

    def on_remove(path):
        print(f"⏏️  USB REMOVED:  {path}")

    detector = USBDetector(on_insert=on_insert, on_remove=on_remove)
    print(f"USB Detector starting on {platform.system()}...")
    print("Plug in or remove a USB drive. Press Ctrl+C to stop.\n")
    detector.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        detector.stop()
        print("\nStopped.")

"""
usb_detector.py
---------------
Cross-platform USB / removable-volume detection.

Two responsibilities:

1. ``list_removable_mounts()`` — a point-in-time snapshot of mounted
   removable volumes. This is the single implementation used by the CLI,
   the API's ``/api/status`` and ``/api/mounts``, and the polling monitors.
   It replaces a Linux-only mount probe that made ``usb_detected`` always
   false on Windows and macOS.

2. ``USBDetector`` — a background watcher that fires callbacks on insert
   and removal.

Detection strategy per platform:
- Linux:   pyudev (udev netlink) when available, else mount polling
- Windows: GetLogicalDrives + GetDriveTypeW polling (no dependencies);
           WMI is used only if explicitly requested and importable
- macOS:   /Volumes polling, excluding the boot volume
"""

import os
import time
import platform
import threading
from pathlib import Path

POLL_INTERVAL_SECONDS = 2.0

# Volumes that are mounted but are not user data drives.
_MACOS_EXCLUDED_VOLUMES = {".timemachine", "Recovery", "Preboot", "VM", "Update"}


# ──────────────────────────────────────────────
# Linux helpers
# ──────────────────────────────────────────────
def _linux_block_device_name(device_path: str) -> str | None:
    """
    Map a device node to its parent block device name, resolving through
    /sys so partition schemes are handled correctly.

    A regex that strips trailing digits turns 'nvme0n1p3' into 'nvme0n1p'
    (which does not exist) and 'mmcblk0p1' into 'mmcblk0p'. Walking /sys
    avoids guessing.
    """
    name = os.path.basename(os.path.realpath(device_path))
    if not name:
        return None

    # A partition's sysfs dir lives under its parent disk.
    sys_block = Path("/sys/class/block") / name
    if sys_block.exists():
        parent = sys_block.resolve().parent
        if (parent / "removable").exists():
            return parent.name
        # Already a whole disk.
        if (sys_block / "removable").exists():
            return name

    return name


def _linux_is_removable(device_path: str) -> bool:
    """True when the backing block device reports removable, or sits on USB."""
    devname = _linux_block_device_name(device_path)
    if not devname:
        return False

    removable = Path(f"/sys/block/{devname}/removable")
    try:
        if removable.exists() and removable.read_text().strip() == "1":
            return True
    except OSError:
        pass

    # USB-attached SSDs report removable=0 but are still external. The device
    # symlink target contains the bus path, e.g. .../usb2/2-1/2-1:1.0/...
    try:
        link = os.path.realpath(f"/sys/block/{devname}")
        if "/usb" in link:
            return True
    except OSError:
        pass

    return False


def _linux_mounts() -> list[tuple[str, str]]:
    """Parse /proc/mounts into (device, mount_point) pairs."""
    entries = []
    try:
        with open("/proc/mounts", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    entries.append((parts[0], _unescape_mount_path(parts[1])))
    except OSError:
        pass
    return entries


def _unescape_mount_path(path: str) -> str:
    r"""
    Decode the octal escapes the kernel writes into /proc/mounts
    (space -> \040, tab -> \011).

    The previous raw_unicode_escape round-trip mangled non-ASCII volume
    labels, so a drive named 'Datos Añejos' produced an unusable path.
    """
    if "\\" not in path:
        return path

    out = []
    i = 0
    while i < len(path):
        if path[i] == "\\" and i + 3 < len(path) + 1 and path[i + 1:i + 4].isdigit():
            try:
                out.append(chr(int(path[i + 1:i + 4], 8)))
                i += 4
                continue
            except ValueError:
                pass
        out.append(path[i])
        i += 1
    return "".join(out)


def _linux_removable_mounts() -> set[str]:
    """Removable mount points on Linux."""
    mounts = set()

    for device, mount_point in _linux_mounts():
        if not device.startswith("/dev/"):
            continue
        # Ignore the roots that are never removable media.
        if mount_point in ("/", "/boot", "/boot/efi", "/home"):
            continue
        if _linux_is_removable(device):
            mounts.add(mount_point)

    # Also accept anything under the standard auto-mount roots, which covers
    # filesystems whose backing device we could not classify. /mnt is
    # deliberately excluded — network shares live there, and auto-scan must
    # not start quarantining a fileserver.
    user = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
    for base in (f"/run/media/{user}", f"/media/{user}", "/media"):
        if not os.path.isdir(base):
            continue
        try:
            for entry in os.listdir(base):
                full = os.path.join(base, entry)
                if os.path.ismount(full):
                    mounts.add(full)
        except (PermissionError, OSError):
            pass

    return mounts


# ──────────────────────────────────────────────
# Windows helpers
# ──────────────────────────────────────────────
DRIVE_REMOVABLE = 2
DRIVE_CDROM = 5


def _windows_removable_mounts() -> set[str]:
    """
    Removable drive roots on Windows, e.g. {'E:\\\\'}.

    Uses ctypes against kernel32 so it works in a frozen build with no
    pywin32/WMI dependency.
    """
    drives = set()
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        bitmask = kernel32.GetLogicalDrives()

        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            if bitmask & 1:
                path = f"{letter}:\\"
                drive_type = kernel32.GetDriveTypeW(path)
                if drive_type == DRIVE_REMOVABLE:
                    # A card reader with no card still reports removable but
                    # has no accessible root.
                    if os.path.exists(path):
                        drives.add(path)
            bitmask >>= 1
    except Exception:
        pass
    return drives


# ──────────────────────────────────────────────
# macOS helpers
# ──────────────────────────────────────────────
def _macos_removable_mounts() -> set[str]:
    """
    Mounted volumes under /Volumes excluding the boot volume.

    Identifying the boot volume by name ('Macintosh HD') fails as soon as
    the user renames their disk, so compare device IDs against '/' instead.
    """
    volumes = set()
    volumes_dir = "/Volumes"

    try:
        root_dev = os.stat("/").st_dev
    except OSError:
        root_dev = None

    if not os.path.isdir(volumes_dir):
        return volumes

    try:
        entries = os.listdir(volumes_dir)
    except (PermissionError, OSError):
        return volumes

    for entry in entries:
        if entry in _MACOS_EXCLUDED_VOLUMES:
            continue
        full = os.path.join(volumes_dir, entry)
        try:
            if not os.path.ismount(full):
                continue
            # /Volumes contains a symlink back to the boot volume.
            if root_dev is not None and os.stat(full).st_dev == root_dev:
                continue
        except OSError:
            continue
        volumes.add(full)

    return volumes


# ──────────────────────────────────────────────
# Public snapshot API
# ──────────────────────────────────────────────
def list_removable_mounts() -> list[str]:
    """
    Return currently mounted removable volume paths, sorted for stable UI.
    Safe to call frequently; never raises.
    """
    try:
        system = platform.system()
        if system == "Windows":
            mounts = _windows_removable_mounts()
        elif system == "Darwin":
            mounts = _macos_removable_mounts()
        else:
            mounts = _linux_removable_mounts()
        return sorted(mounts)
    except Exception:
        return []


def find_usb_mount() -> str | None:
    """First detected removable mount, or None. Cross-platform."""
    mounts = list_removable_mounts()
    return mounts[0] if mounts else None


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

    def __init__(self, on_insert=None, on_remove=None, use_wmi=False):
        """
        Args:
            on_insert: Callable(str) — called with mount path when USB is inserted
            on_remove: Callable(str) — called with mount path when USB is removed
            use_wmi:   Windows only — opt in to WMI events instead of polling.
                       Off by default because WMI needs pywin32, which does
                       not survive PyInstaller bundling reliably.
        """
        self.on_insert = on_insert or (lambda path: None)
        self.on_remove = on_remove or (lambda path: None)
        self.use_wmi = use_wmi
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
            target = self._poll_monitor
        else:
            raise OSError(f"Unsupported platform: {self._system}")

        self._thread = threading.Thread(target=target, daemon=True,
                                        name="usb-detector")
        self._thread.start()

    def stop(self):
        """Signal the monitor to stop."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=POLL_INTERVAL_SECONDS + 2)
            self._thread = None

    def _safe_insert(self, path):
        """Never let a callback exception kill the monitor thread."""
        try:
            self.on_insert(path)
        except Exception as e:
            print(f"[usb_detector] on_insert callback failed: {e}", flush=True)

    def _safe_remove(self, path):
        try:
            self.on_remove(path)
        except Exception as e:
            print(f"[usb_detector] on_remove callback failed: {e}", flush=True)

    # ──────────────────────────────────────────────
    # Generic polling monitor (macOS, and fallback everywhere)
    # ──────────────────────────────────────────────
    def _poll_monitor(self):
        """Diff the removable-mount snapshot on an interval."""
        known = set(list_removable_mounts())

        while not self._stop_event.is_set():
            if self._stop_event.wait(POLL_INTERVAL_SECONDS):
                break

            current = set(list_removable_mounts())

            for mount in sorted(current - known):
                self._safe_insert(mount)
            for mount in sorted(known - current):
                self._safe_remove(mount)

            known = current

    # ──────────────────────────────────────────────
    # Linux: pyudev-based udev monitoring
    # ──────────────────────────────────────────────
    def _linux_monitor(self):
        """Monitor USB events via pyudev (udev subsystem)."""
        try:
            import pyudev
        except ImportError:
            # Expected on minimal systems — polling is fully functional.
            print("[usb_detector] pyudev unavailable, using mount polling", flush=True)
            self._poll_monitor()
            return

        try:
            context = pyudev.Context()
            monitor = pyudev.Monitor.from_netlink(context)
            monitor.filter_by(subsystem='block', device_type='partition')
            monitor.start()
        except Exception as e:
            print(f"[usb_detector] udev unavailable ({e}), using mount polling", flush=True)
            self._poll_monitor()
            return

        while not self._stop_event.is_set():
            try:
                device = monitor.poll(timeout=1)
            except Exception:
                continue

            if device is None:
                continue

            action = device.action          # 'add', 'remove', 'change'
            dev_node = device.device_node   # e.g., /dev/sdb1

            if action == 'add':
                mount_path = self._wait_for_linux_mount(dev_node, timeout=10)
                if mount_path:
                    self._safe_insert(mount_path)

            elif action == 'remove':
                self._safe_remove(dev_node or "unknown")

    def _wait_for_linux_mount(self, dev_node, timeout=10):
        """
        After a partition 'add' event, wait for it to be mounted.
        Returns the mount path or None if it never appeared.
        """
        deadline = time.time() + timeout

        while time.time() < deadline:
            if self._stop_event.is_set():
                return None

            for device, mount_point in _linux_mounts():
                if device == dev_node:
                    return mount_point

            if self._stop_event.wait(0.5):
                return None

        return None

    # ──────────────────────────────────────────────
    # Windows: drive-letter polling (WMI optional)
    # ──────────────────────────────────────────────
    def _windows_monitor(self):
        """
        Monitor removable drives on Windows.

        Polling is the default: it needs nothing beyond ctypes, survives
        PyInstaller bundling, and detects the mount (not just the device
        arrival) which is what a scan actually needs.
        """
        if not self.use_wmi:
            self._poll_monitor()
            return

        try:
            import wmi
        except ImportError:
            print("[usb_detector] wmi requested but unavailable, using polling", flush=True)
            self._poll_monitor()
            return

        try:
            c = wmi.WMI()
            watcher = c.Win32_VolumeChangeEvent.watch_for(EventType=2)  # arrival
        except Exception as e:
            print(f"[usb_detector] WMI setup failed ({e}), using polling", flush=True)
            self._poll_monitor()
            return

        while not self._stop_event.is_set():
            try:
                event = watcher(timeout_ms=1000)
            except Exception:
                continue  # WMI timeout is normal

            if not event:
                continue

            drive = getattr(event, "DriveName", None)
            if not drive:
                continue

            mount_path = drive if drive.endswith("\\") else drive + "\\"
            if os.path.exists(mount_path):
                self._safe_insert(mount_path)


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
    print(f"Currently mounted removable volumes: {list_removable_mounts() or 'none'}")
    print("Plug in or remove a USB drive. Press Ctrl+C to stop.\n")
    detector.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        detector.stop()
        print("\nStopped.")

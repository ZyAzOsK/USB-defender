#!/usr/bin/env python3
"""
main.py
-------
USB-Defender CLI entry point.
Detects USB mount points and provides scan/monitor operations.
"""

import os
import platform
import argparse
from pathlib import Path
from db import init_db
from scanner import scan_target
from watcher import start_monitoring


def find_usb_mount():
    """Auto-detect USB mount point on Linux, prioritizing removable drives."""
    try:
        username = os.getlogin()
    except OSError:
        username = os.environ.get("USER", "")

    possible_paths = [f"/run/media/{username}", f"/media/{username}"]

    # Keep track of the first mount we find, in case we can't determine removability
    fallback_mount = None

    for path in possible_paths:
        if os.path.exists(path):
            for device in os.listdir(path):
                mount_path = os.path.join(path, device)
                if os.path.ismount(mount_path):
                    # Check if it's actually removable (e.g. skip Windows-SSD)
                    if is_block_device_removable(mount_path):
                        return mount_path
                    if fallback_mount is None:
                        fallback_mount = mount_path
                        
    return fallback_mount


def get_mount_root_of_path(p: Path) -> Path:
    """Walk up from a path to find its mount root."""
    p = p.resolve()
    if platform.system() == "Windows":
        return Path(p.anchor)
    else:
        prev_dev = os.stat(p).st_dev
        cur = p
        while True:
            parent = cur.parent
            if parent == cur:
                return cur
            try:
                parent_dev = os.stat(parent).st_dev
            except FileNotFoundError:
                return cur
            if parent_dev != prev_dev:
                return cur
            cur = parent
            prev_dev = parent_dev


def detect_usb_root_from_script() -> str:
    """Detect USB root based on where this script is running from."""
    running_file = Path(__file__).resolve()
    mount_root = get_mount_root_of_path(running_file)
    return str(mount_root)


def parse_args():
    p = argparse.ArgumentParser(description="USB Defender — Portable USB Security Tool")
    p.add_argument("--path", "-p",
                    help="Path to operate on. If omitted, auto-detects USB mount.",
                    default=None)
    p.add_argument("--require-removable", action="store_true",
                    help="Ensure target is a removable device (Linux only).")
    p.add_argument("--scan", action="store_true",
                    help="Run one-time scan (non-interactive mode).")
    p.add_argument("--monitor", action="store_true",
                    help="Start real-time monitoring (non-interactive mode).")
    return p.parse_args()


def is_block_device_removable(mount_path: str) -> bool:
    """Linux: check if a mount corresponds to a removable block device."""
    try:
        import re
        with open("/proc/mounts", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == mount_path:
                    dev = parts[0]
                    devname = os.path.basename(dev)
                    devbase = re.sub(r"\d+$", "", devname)
                    removable_path = f"/sys/block/{devbase}/removable"
                    if os.path.exists(removable_path):
                        with open(removable_path, "r") as r:
                            val = r.read().strip()
                            return val == "1"
                    return False
    except Exception:
        return False
    return False


def main():
    # === Initialize database on startup ===
    init_db()

    args = parse_args()
    usb_mount = find_usb_mount()
    usb_script_mount = detect_usb_root_from_script()

    # Decide target mount
    if args.path:
        target = args.path
    elif usb_mount:
        target = usb_mount
    else:
        target = usb_script_mount

    if not os.path.exists(target):
        print(f"[ERROR] target path does not exist: {target}")
        return

    if platform.system() != "Windows" and args.require_removable:
        if not is_block_device_removable(target):
            print("[ERROR] target is not a removable block device (or detection failed). Exiting.")
            return

    log_path = os.path.join(os.path.dirname(__file__), "logs")
    os.makedirs(log_path, exist_ok=True)

    # Non-interactive mode (for sidecar/API usage)
    if args.scan:
        print(f"Operating on target mount: {target}\n")
        scan_target(target)
        return
    if args.monitor:
        print(f"Operating on target mount: {target}\n")
        start_monitoring(target, log_path)
        return

    # Interactive mode
    print(f"Operating on target mount: {target}\n")
    print("Choose an action:")
    print("1. Run a one-time scan")
    print("2. Start real-time monitoring")

    choice = input("\nEnter your choice (1 or 2): ").strip()

    if choice == "1":
        scan_target(target)
    elif choice == "2":
        start_monitoring(target, log_path)
    else:
        print("Invalid choice. Exiting...")


if __name__ == "__main__":
    main()

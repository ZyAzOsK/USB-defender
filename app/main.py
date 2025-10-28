#!/usr/bin/env python3
import os
import platform
import argparse
from scanner import scan_usb
from pathlib import Path


def get_usb_path():
    """Mount point detection of USB stick via this script."""
    current_path = os.path.abspath(__file__)
    if platform.system() == "Windows":
        drive = os.path.splitdrive(current_path)[0] + "\\"
        return drive
    else:
        parts = current_path.split(os.sep)
        for i in range(len(parts), 0, -1):
            path = os.sep.join(parts[:i])
            if os.path.ismount(path):
                return path
        return "/"
    
if __name__ == "__main__":
    usb_path = get_usb_path()
    print(f"USB Path Detected: {usb_path}")

    log_path = os.path.join(os.path.dirname(__file__), "logs")
    scan_usb(usb_path, log_path)

def get_mount_root_of_path(p: Path) -> Path:
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
    # if run from a source tree, __file__ will be in that tree; if run from USB, this resolves to USB path.
    running_file = Path(__file__).resolve()
    mount_root = get_mount_root_of_path(running_file)
    return str(mount_root)

def parse_args():
    p = argparse.ArgumentParser(description="USB Threat Behavior Logger")
    p.add_argument("--path", "-p", help="(DEV) Path to operate on. If omitted, app uses the mount of this script.", default=None)
    p.add_argument("--require-removable", action="store_true", help="(Optional) ensure target mount is a removable device (Linux).")
    return p.parse_args()

def is_block_device_removable(mount_path: str) -> bool:
    """
    Linux: check /proc/mounts -> device -> /sys/block/<dev>/removable
    Returns False on failure or if not removable.
    """
    try:
        import re
        # find device for mount
        with open("/proc/mounts", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == mount_path:
                    dev = parts[0]  # e.g. /dev/sdb1
                    # simplify to block (sdb)
                    devname = os.path.basename(dev)
                    # strip partition number (e.g., sdb1 -> sdb)
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
    args = parse_args()
    if args.path:
        target = args.path
    else:
        target = detect_usb_root_from_script()

    if not os.path.exists(target):
        print(f"[ERROR] target path does not exist: {target}")
        return

    if platform.system() != "Windows" and args.require_removable:
        if not is_block_device_removable(target):
            print("[ERROR] target is not a removable block device (or detection failed). Exiting.")
            return

    print(f"Operating on target mount: {target}")
    # from here on, use 'target' as your usb_root for watcher/scans
    # e.g., pass to scan_initial_files(target), start_watcher(target), etc.

if __name__ == "__main__":
    main()

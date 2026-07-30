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
from db import init_db, LOG_DIR
from scanner import scan_target
from watcher import start_monitoring
from paths import normalize_target_path, check_scan_target
from usb_detector import find_usb_mount, list_removable_mounts

# find_usb_mount is re-exported from usb_detector so api.py and the CLI share
# one cross-platform implementation. The previous local copy only searched
# /run/media and /media, so it always returned None on Windows and macOS.
__all__ = ["find_usb_mount", "list_removable_mounts", "main"]


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
                    help="Ensure target is a removable device before operating on it.")
    p.add_argument("--scan", action="store_true",
                    help="Run one-time scan (non-interactive mode).")
    p.add_argument("--monitor", action="store_true",
                    help="Start real-time monitoring (non-interactive mode).")
    return p.parse_args()


def is_block_device_removable(mount_path: str) -> bool:
    """
    Check whether a mount point corresponds to removable media.
    Cross-platform: delegates to the shared detector rather than parsing
    /proc/mounts with a partition-name regex that broke on NVMe and eMMC.
    """
    return mount_path in list_removable_mounts()


def main():
    # === Initialize database on startup ===
    init_db()

    args = parse_args()

    # Decide target mount
    if args.path:
        target = normalize_target_path(args.path)
    else:
        target = find_usb_mount() or detect_usb_root_from_script()

    problem = check_scan_target(target)
    if problem:
        print(f"[ERROR] {problem}")
        return

    if args.require_removable and not is_block_device_removable(target):
        print("[ERROR] target is not a removable device (or detection failed). Exiting.")
        return

    log_path = str(LOG_DIR)

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

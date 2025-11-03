#!/usr/bin/env python3
import os
import platform
import argparse
import psutil
from pathlib import Path
from scanner import scan_target
from watcher import start_monitoring



def find_usb_mount():
    username = os.getlogin()
    possible_paths = [f"/run/media/{username}", f"/media/{username}"]

    for path in possible_paths:
        if os.path.exists(path):
            for device in os.listdir(path):
                mount_path = os.path.join(path, device)
                if os.path.ismount(mount_path):
                    return mount_path
    return None


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
    running_file = Path(__file__).resolve()
    mount_root = get_mount_root_of_path(running_file)
    return str(mount_root)


def parse_args():
    p = argparse.ArgumentParser(description="USB Threat Behavior Logger")
    p.add_argument("--path", "-p", help="(DEV) Path to operate on. If omitted, app uses detected USB mount.", default=None)
    p.add_argument("--require-removable", action="store_true", help="Ensure target is a removable device (Linux only).")
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

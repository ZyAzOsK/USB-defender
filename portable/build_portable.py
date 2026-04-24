#!/usr/bin/env python3
"""
Build script for USB Defender Portable Scanner.
Creates a single-file executable using PyInstaller.

Usage:
    python build_portable.py                # Build for current platform
    python build_portable.py --onedir       # Build as directory (faster startup)
    python build_portable.py --name MyUSB   # Custom output name

Requirements:
    pip install pyinstaller
"""

import subprocess
import sys
import platform
import argparse
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
MAIN_SCRIPT = SCRIPT_DIR / "usb_defender_portable.py"
DIST_DIR = SCRIPT_DIR / "dist"


def build(onedir=False, name=None):
    """Build the portable scanner binary."""
    if not MAIN_SCRIPT.exists():
        print(f"ERROR: {MAIN_SCRIPT} not found!")
        sys.exit(1)

    # Determine output name
    if name is None:
        system = platform.system().lower()
        if system == "windows":
            name = "USBDefender"
        elif system == "darwin":
            name = "usb-defender-macos"
        else:
            name = "usb-defender-linux"

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--clean",
        "--noconfirm",
        "--name", name,
        "--distpath", str(DIST_DIR),
        "--workpath", str(SCRIPT_DIR / "build"),
        "--specpath", str(SCRIPT_DIR),
    ]

    if onedir:
        cmd.append("--onedir")
    else:
        cmd.append("--onefile")

    # Platform-specific options
    if platform.system() == "Windows":
        cmd.append("--console")  # Keep console window for scanner output

    cmd.append(str(MAIN_SCRIPT))

    print(f"\n🔨 Building USB Defender Portable...")
    print(f"   Platform: {platform.system()} {platform.machine()}")
    print(f"   Mode:     {'onedir' if onedir else 'onefile'}")
    print(f"   Output:   {DIST_DIR / name}")
    print(f"   Command:  {' '.join(cmd)}\n")

    result = subprocess.run(cmd)

    if result.returncode == 0:
        if onedir:
            output = DIST_DIR / name
        else:
            ext = ".exe" if platform.system() == "Windows" else ""
            output = DIST_DIR / f"{name}{ext}"

        print(f"\n✅ Build successful!")
        print(f"   Binary: {output}")
        print(f"\n📋 Next steps:")
        print(f"   1. Copy '{output}' to the root of your USB drive")
        print(f"   2. On any PC, double-click (Windows) or run ./{name} (Linux/Mac)")
        print(f"   3. The scanner will automatically detect and scan the USB\n")
    else:
        print(f"\n❌ Build failed with exit code {result.returncode}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Build USB Defender Portable Scanner")
    parser.add_argument("--onedir", action="store_true",
                       help="Build as directory instead of single file (faster startup)")
    parser.add_argument("--name", type=str, default=None,
                       help="Custom name for the output binary")
    args = parser.parse_args()

    build(onedir=args.onedir, name=args.name)


if __name__ == "__main__":
    main()

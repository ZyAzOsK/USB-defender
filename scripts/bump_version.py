#!/usr/bin/env python3
"""
bump_version.py
---------------
Set the release version in every place that declares one.

The v1.0.2 tag shipped installers named "USB Defender_1.0.0_..." because the
version lived in five files and only some were updated. CI now refuses to
publish when the tag and tauri.conf.json disagree; this script is how you make
them agree.

Usage:
    python scripts/bump_version.py 1.0.3
    python scripts/bump_version.py --check      # verify all sources match
"""

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

TAURI_CONF = ROOT / "dashboard" / "src-tauri" / "tauri.conf.json"
CARGO_TOML = ROOT / "dashboard" / "src-tauri" / "Cargo.toml"
API_PY = ROOT / "app" / "api.py"
PORTABLE_PY = ROOT / "portable" / "usb_defender_portable.py"
API_TS = ROOT / "dashboard" / "src" / "api.ts"

VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


def read_versions() -> dict[str, str | None]:
    """Current version according to each source of truth."""
    versions: dict[str, str | None] = {}

    try:
        versions["tauri.conf.json"] = json.loads(TAURI_CONF.read_text(encoding="utf-8"))["version"]
    except (OSError, KeyError, json.JSONDecodeError):
        versions["tauri.conf.json"] = None

    def first_group(path: Path, pattern: str) -> str | None:
        try:
            match = re.search(pattern, path.read_text(encoding="utf-8"), re.MULTILINE)
            return match.group(1) if match else None
        except OSError:
            return None

    versions["Cargo.toml"] = first_group(CARGO_TOML, r'^version\s*=\s*"([^"]+)"')
    versions["app/api.py"] = first_group(API_PY, r'^APP_VERSION\s*=\s*"([^"]+)"')
    versions["portable scanner"] = first_group(PORTABLE_PY, r'^VERSION\s*=\s*"([^"]+)"')
    versions["dashboard/src/api.ts"] = first_group(
        API_TS, r'^export const APP_VERSION\s*=\s*"([^"]+)"'
    )

    return versions


def substitute(path: Path, pattern: str, replacement: str) -> bool:
    """Apply a single-line regex substitution; True when the file changed."""
    original = path.read_text(encoding="utf-8")
    updated, count = re.subn(pattern, replacement, original, count=1, flags=re.MULTILINE)
    if count == 0:
        print(f"  WARNING: no match in {path.relative_to(ROOT)}")
        return False
    if updated == original:
        return False
    path.write_text(updated, encoding="utf-8")
    return True


def write_versions(version: str) -> None:
    print(f"Setting version to {version}")

    conf = json.loads(TAURI_CONF.read_text(encoding="utf-8"))
    if conf.get("version") != version:
        conf["version"] = version
        TAURI_CONF.write_text(json.dumps(conf, indent=2) + "\n", encoding="utf-8")
        print("  updated dashboard/src-tauri/tauri.conf.json")

    targets = [
        (CARGO_TOML, r'^version\s*=\s*"[^"]+"', f'version = "{version}"'),
        (API_PY, r'^APP_VERSION\s*=\s*"[^"]+"', f'APP_VERSION = "{version}"'),
        (PORTABLE_PY, r'^VERSION\s*=\s*"[^"]+"', f'VERSION = "{version}"'),
        (
            API_TS,
            r'^export const APP_VERSION\s*=\s*"[^"]+"',
            f'export const APP_VERSION = "{version}"',
        ),
    ]

    for path, pattern, replacement in targets:
        if substitute(path, pattern, replacement):
            print(f"  updated {path.relative_to(ROOT)}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Synchronize the release version")
    parser.add_argument("version", nargs="?", help="Version to set, e.g. 1.0.3")
    parser.add_argument("--check", action="store_true",
                        help="Report whether all sources already agree")
    args = parser.parse_args()

    if args.check or not args.version:
        versions = read_versions()
        width = max(len(k) for k in versions)
        for name, value in versions.items():
            print(f"  {name:<{width}}  {value or '(not found)'}")

        distinct = {v for v in versions.values() if v}
        if len(distinct) == 1 and None not in versions.values():
            print(f"\nAll sources agree on {distinct.pop()}")
            return 0
        print("\nMISMATCH — run: python scripts/bump_version.py <version>")
        return 1

    if not VERSION_RE.match(args.version):
        print(f"'{args.version}' is not a semantic version like 1.0.3")
        return 2

    write_versions(args.version)
    print("\nVerifying:")
    return main_check()


def main_check() -> int:
    versions = read_versions()
    distinct = {v for v in versions.values() if v}
    for name, value in versions.items():
        print(f"  {name}: {value}")
    if len(distinct) == 1:
        print(f"\nAll sources agree on {distinct.pop()}")
        return 0
    print("\nStill mismatched")
    return 1


if __name__ == "__main__":
    sys.exit(main())

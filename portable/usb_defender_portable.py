#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════╗
║           USB DEFENDER — PORTABLE SCANNER                 ║
║  Zero-dependency, single-file USB security scanner.       ║
║  Lives on the USB drive itself. Works on any PC.          ║
╚═══════════════════════════════════════════════════════════╝

Usage:
    python usb_defender_portable.py              # Auto-detect USB root
    python usb_defender_portable.py --path /mnt  # Scan a specific path
    python usb_defender_portable.py --no-quarantine  # Report only, don't quarantine
    python usb_defender_portable.py --restore        # Restore quarantined files
    python usb_defender_portable.py --ai-key KEY     # Use Gemini AI for analysis

This file is fully self-contained. No pip install needed.
Works with Python 3.8+ (ships with every modern OS).
"""

import os
import sys
import json
import hashlib
import shutil
import uuid
import time
import platform
import argparse
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ======================================================================
# CONFIGURATION
# ======================================================================
VERSION = "1.1.0"
MAX_HEURISTIC_SIZE = 5 * 1024 * 1024   # 5 MB — skip content scan for larger files
MAX_HASH_SIZE = 100 * 1024 * 1024       # 100 MB — skip SHA256 for files larger than this
MAX_WORKERS = 8                          # Parallel scan threads
QUARANTINE_SEVERITY_THRESHOLD = 8        # Auto-quarantine at this severity or above
MIN_PATTERN_MATCHES = 2                  # Require 2+ pattern matches for heuristic flags
SELF_FILENAME = "usb_defender_portable.py"  # Skip scanning ourselves

# Directories to skip entirely (dev/system dirs — not user threat vectors)
SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    ".svn", ".hg", "bower_components", ".tox", ".eggs",
    "System Volume Information", "$RECYCLE.BIN",
}

# Extensions to skip entirely (large binaries, media, archives — no malware risk)
SKIP_EXTENSIONS = {
    ".iso", ".img", ".vmdk", ".vdi", ".vhd", ".ova",     # Disk images
    ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv",      # Video
    ".mp3", ".flac", ".wav", ".aac", ".ogg", ".wma",     # Audio
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", # Archives
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp",    # Images
    ".pdf",                                                # Documents
    ".ttf", ".otf", ".woff", ".woff2",                    # Fonts
    ".so", ".dylib", ".dll",                               # Shared libs
    ".qfile",                                              # Already quarantined
}

# ======================================================================
# EMBEDDED SIGNATURES (self-contained, no JSON file needed)
# ======================================================================
KNOWN_BAD_HASHES = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR_SHA256",
    "44d88612fea8a8f36de82e1278abb02f": "EICAR_MD5",
}

HEURISTIC_RULES = [
    {
        "name": "Suspicious_HTML_Executable",
        "patterns": ["<script>", "powershell", "cmd.exe", "base64,"],
        "extensions": [".html", ".htm", ".txt"],
    },
    {
        "name": "Potential_Malicious_Python",
        "patterns": ["import os", "exec(", "subprocess", "socket"],
        "extensions": [".py"],
    },
    {
        "name": "Suspicious_Batch_Script",
        "patterns": ["del /f", "del /s", "del /q", "c:\\windows", "format ",
                     "net user", "reg add", "reg delete", "taskkill"],
        "extensions": [".bat", ".cmd"],
    },
    {
        "name": "Suspicious_PowerShell_Script",
        "patterns": ["invoke-webrequest", "iex", "downloadstring",
                     "-encodedcommand", "invoke-expression", "new-object net.webclient"],
        "extensions": [".ps1"],
    },
    {
        "name": "Suspicious_VBS_Script",
        "patterns": ["wscript.shell", "createobject", "activexobject", "shell.application"],
        "extensions": [".vbs", ".js", ".wsf"],
    },
]

# ======================================================================
# EMBEDDED THREAT INTELLIGENCE
# ======================================================================
THREAT_INTEL = {
    "Known_Malware_Hash":        {"severity": 10, "category": "Malware",                "action": "Quarantine immediately"},
    "EICAR_SHA256":              {"severity": 10, "category": "Malware (Test)",          "action": "Quarantine immediately"},
    "EICAR_MD5":                 {"severity": 10, "category": "Malware (Test)",          "action": "Quarantine immediately"},
    "Suspicious_HTML_Executable":{"severity": 8,  "category": "Script Injection",        "action": "Inspect and delete if untrusted"},
    "Potential_Malicious_Python": {"severity": 7,  "category": "Code Execution",         "action": "Review script"},
    "Suspicious_Batch_Script":   {"severity": 8,  "category": "System Manipulation",     "action": "Inspect batch file"},
    "Suspicious_PowerShell_Script":{"severity": 9,"category": "Remote Code Execution",   "action": "Quarantine and review"},
    "Suspicious_VBS_Script":     {"severity": 8,  "category": "Script Injection",        "action": "Inspect for shell payloads"},
    "Clean":                     {"severity": 0,  "category": "Benign",                  "action": "No action needed"},
}


# ======================================================================
# TERMINAL COLORS (works on Windows 10+, Linux, macOS)
# ======================================================================
class Colors:
    """ANSI color codes for terminal output."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BG_RED  = "\033[41m"
    BG_GREEN = "\033[42m"

    @staticmethod
    def enable():
        """Enable ANSI colors on Windows."""
        if platform.system() == "Windows":
            os.system("")  # Enables ANSI escape sequences on Windows 10+


# ======================================================================
# UTILITY FUNCTIONS
# ======================================================================
def compute_sha256(file_path):
    """Compute SHA256 hash of a file."""
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (OSError, PermissionError):
        return None


def get_usb_root():
    """Detect USB root based on where this script is running from."""
    script_path = Path(__file__).resolve()
    
    if platform.system() == "Windows":
        # On Windows, the drive letter is the root (e.g. E:\)
        return Path(script_path.anchor)
    else:
        # On Linux/macOS, walk up to find the mount point
        p = script_path
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


def format_size(size_bytes):
    """Human-readable file size."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024*1024):.1f} MB"
    return f"{size_bytes / (1024*1024*1024):.1f} GB"


# ======================================================================
# SIGNATURE MATCHING ENGINE
# ======================================================================
def match_file(file_path):
    """
    Scan a file against all embedded signatures and heuristic rules.
    Returns: (is_suspicious: bool, tags: list[str])
    """
    tags = []
    ext = Path(file_path).suffix.lower()
    basename = Path(file_path).name

    # Skip the scanner's own file
    if basename == SELF_FILENAME:
        return False, []

    # Skip known-safe large binary extensions entirely
    if ext in SKIP_EXTENSIONS:
        return False, []

    try:
        file_size = os.path.getsize(file_path)
    except OSError:
        file_size = 0

    # 1. Hash-based detection (skip for huge files)
    if 0 < file_size <= MAX_HASH_SIZE:
        sha256 = compute_sha256(file_path)
        if sha256 and sha256 in KNOWN_BAD_HASHES:
            tags.append(KNOWN_BAD_HASHES[sha256])

    # 2. Heuristic content scanning (with OOM protection)
    if 0 < file_size <= MAX_HEURISTIC_SIZE:
        try:
            with open(file_path, "r", errors="ignore") as f:
                content = f.read().lower()

            for rule in HEURISTIC_RULES:
                if ext in rule["extensions"]:
                    # Count how many patterns match — require MIN_PATTERN_MATCHES
                    matched = sum(1 for p in rule["patterns"] if p.lower() in content)
                    if matched >= MIN_PATTERN_MATCHES:
                        if rule["name"] not in tags:
                            tags.append(rule["name"])
        except Exception:
            pass

    if tags:
        return True, tags
    return False, []


def enrich_tag(tag):
    """Return full threat context for a given tag."""
    info = THREAT_INTEL.get(tag, {
        "severity": 1, "category": "Unknown", "action": "Manual review recommended"
    })
    return {"tag": tag, **info}


# ======================================================================
# QUARANTINE ENGINE (XOR-based, no external crypto needed)
# ======================================================================
XOR_KEY = b"USB_DEFENDER_PORTABLE_KEY_2024"


def xor_encrypt(data, key):
    """Simple XOR encryption to neutralize file payloads."""
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def quarantine_file(file_path, info, quarantine_dir):
    """Move and XOR-encrypt a malicious file into quarantine."""
    try:
        os.makedirs(quarantine_dir, exist_ok=True)

        quarantine_id = str(uuid.uuid4())
        quarantine_path = os.path.join(quarantine_dir, f"{quarantine_id}.qfile")
        metadata_file = os.path.join(quarantine_dir, f"{quarantine_id}.meta.json")

        # Read & encrypt
        with open(file_path, "rb") as f:
            original_data = f.read()

        encrypted_data = xor_encrypt(original_data, XOR_KEY)

        # Write encrypted quarantine file
        with open(quarantine_path, "wb") as f:
            f.write(encrypted_data)

        # Remove original
        os.remove(file_path)

        # Write metadata
        metadata = {
            "id": quarantine_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "original_path": str(file_path),
            "quarantine_path": quarantine_path,
            "tag": info.get("tag"),
            "severity": info.get("severity"),
            "category": info.get("category"),
            "action": info.get("action"),
            "scanner": "USB Defender Portable",
            "version": VERSION,
        }
        with open(metadata_file, "w") as f:
            json.dump(metadata, f, indent=4)

        return True, quarantine_path
    except Exception as e:
        return False, str(e)


# ======================================================================
# SCAN ENGINE
# ======================================================================
def scan_single_file(file_path, target_path, do_quarantine, quarantine_dir):
    """Scan a single file with heuristics (no AI — that runs in a separate pass)."""
    rel_path = os.path.relpath(file_path, target_path)

    try:
        file_size = os.path.getsize(file_path)
    except OSError:
        file_size = 0

    is_suspicious, tags = match_file(file_path)

    if not is_suspicious:
        return {
            "rel_path": rel_path,
            "file_path": file_path,
            "file_size": file_size,
            "detected": False,
            "tags": [],
            "infos": [enrich_tag("Clean")],
            "quarantined": False,
            "ai_verdict": None,
        }
    else:
        infos = [enrich_tag(tag) for tag in tags]
        return {
            "rel_path": rel_path,
            "file_path": file_path,
            "file_size": file_size,
            "detected": True,
            "tags": tags,
            "infos": infos,
            "quarantined": False,
            "ai_verdict": None,
        }


# ======================================================================
# REPORT GENERATOR
# ======================================================================
def generate_report(results, target_path, scan_time, report_path):
    """Generate a JSON scan report on the USB drive."""
    detected_files = [r for r in results if r["detected"]]
    clean_files = [r for r in results if not r["detected"]]
    quarantined_files = [r for r in results if r.get("quarantined")]

    report = {
        "scanner": "USB Defender Portable",
        "version": VERSION,
        "scan_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_duration_seconds": round(scan_time, 2),
        "target_path": str(target_path),
        "platform": f"{platform.system()} {platform.release()}",
        "summary": {
            "total_files": len(results),
            "clean": len(clean_files),
            "threats_detected": len(detected_files),
            "quarantined": len(quarantined_files),
        },
        "threats": [
            {
                "file": r["rel_path"],
                "size": format_size(r["file_size"]),
                "tags": r["tags"],
                "severity": max(i["severity"] for i in r["infos"]),
                "category": r["infos"][0]["category"],
                "quarantined": r.get("quarantined", False),
            }
            for r in detected_files
        ],
    }

    try:
        with open(report_path, "w") as f:
            json.dump(report, f, indent=4)
        return True
    except Exception:
        return False


# ======================================================================
# MAIN SCANNER
# ======================================================================
def print_banner():
    """Print the startup banner."""
    C = Colors
    print(f"""
{C.CYAN}{C.BOLD}╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ██╗   ██╗███████╗██████╗     ██████╗ ███████╗███████╗   ║
║   ██║   ██║██╔════╝██╔══██╗    ██╔══██╗██╔════╝██╔════╝   ║
║   ██║   ██║███████╗██████╔╝    ██║  ██║█████╗  █████╗     ║
║   ██║   ██║╚════██║██╔══██╗    ██║  ██║██╔══╝  ██╔══╝     ║
║   ╚██████╔╝███████║██████╔╝    ██████╔╝███████╗██║        ║
║    ╚═════╝ ╚══════╝╚═════╝     ╚═════╝ ╚══════╝╚═╝        ║
║                                                           ║
║          P O R T A B L E   S C A N N E R                  ║
║                    v{VERSION}                                ║
╚═══════════════════════════════════════════════════════════╝{C.RESET}
""")


def print_progress(current, total, bar_length=40):
    """Print a progress bar to the terminal."""
    fraction = current / total if total > 0 else 1
    filled = int(bar_length * fraction)
    bar = "█" * filled + "░" * (bar_length - filled)
    percent = fraction * 100
    sys.stdout.write(f"\r  {Colors.CYAN}[{bar}]{Colors.RESET} {percent:5.1f}% ({current}/{total})")
    sys.stdout.flush()


def run_scan(target_path, do_quarantine=True, ai_key=None):
    """Execute the full scan pipeline."""
    C = Colors

    quarantine_dir = os.path.join(target_path, "quarantine")

    # --- Collect files ---
    print(f"\n  {C.DIM}Indexing files...{C.RESET}", end="", flush=True)
    file_paths = []
    for root, dirs, files in os.walk(target_path, followlinks=False):
        # Skip quarantine directory
        if "quarantine" in dirs:
            dirs.remove("quarantine")
        # Skip dev/system directories and hidden directories
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for filename in files:
            # Skip scanner's own files and report files
            if filename in (SELF_FILENAME, "usb_defender_report.json", "scan.sh", "scan.bat"):
                continue
            file_path = os.path.join(root, filename)
            if os.path.islink(file_path):
                continue
            file_paths.append(file_path)

    total = len(file_paths)
    print(f"\r  {C.GREEN}✓{C.RESET} Found {C.BOLD}{total}{C.RESET} files to scan\n")

    if total == 0:
        print(f"  {C.YELLOW}No files found to scan.{C.RESET}")
        return []

    # --- Phase 1: Heuristic scan (parallel, fast) ---
    results = []
    start_time = time.time()
    completed = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_path = {
            executor.submit(scan_single_file, fp, target_path, do_quarantine, quarantine_dir): fp
            for fp in file_paths
        }

        for future in as_completed(future_to_path):
            try:
                result = future.result()
                results.append(result)
            except Exception:
                pass
            completed += 1
            print_progress(completed, total)

    heuristic_time = time.time() - start_time
    print()  # Newline after progress bar

    # --- Phase 2: AI analysis (sequential, respects rate limits) ---
    detected = [r for r in results if r["detected"]]
    hash_tags = set(KNOWN_BAD_HASHES.values()) | {"Known_Malware_Hash"}

    if ai_key and detected:
        ai_candidates = [r for r in detected if not any(t in hash_tags for t in r["tags"])]
        if ai_candidates:
            print(f"\n  {C.CYAN}🤖 Running Gemini AI analysis on {len(ai_candidates)} flagged file(s)...{C.RESET}")
            for i, r in enumerate(ai_candidates):
                fname = Path(r["rel_path"]).name
                print(f"  {C.DIM}  [{i+1}/{len(ai_candidates)}] Analyzing {fname}...{C.RESET}", end="", flush=True)
                is_threat, reason, confidence = gemini_analyze(r["file_path"], r["tags"], ai_key)
                r["ai_verdict"] = {"is_threat": is_threat, "reason": reason, "confidence": confidence}

                if is_threat:
                    print(f"\r  {C.RED}  ⚠ {fname}: {reason}{C.RESET}                    ")
                else:
                    print(f"\r  {C.GREEN}  ✓ {fname}: {reason}{C.RESET}                    ")
                    r["detected"] = False  # AI cleared it

                # Wait between calls to avoid rate limiting
                if i < len(ai_candidates) - 1:
                    time.sleep(4)

    # --- Phase 3: Quarantine confirmed threats ---
    detected = [r for r in results if r["detected"]]  # Re-filter after AI
    if do_quarantine:
        for r in detected:
            max_severity = max(info["severity"] for info in r["infos"])
            fp = r["file_path"]
            if max_severity >= QUARANTINE_SEVERITY_THRESHOLD and os.path.exists(fp):
                success, _ = quarantine_file(fp, r["infos"][0], quarantine_dir)
                r["quarantined"] = success

    scan_time = time.time() - start_time

    # --- Results ---
    detected = [r for r in results if r["detected"]]
    quarantined = [r for r in results if r.get("quarantined")]
    clean_count = len(results) - len(detected)

    print(f"\n  {C.BOLD}{'═' * 55}{C.RESET}")
    print(f"  {C.BOLD}  SCAN RESULTS{C.RESET}")
    print(f"  {C.BOLD}{'═' * 55}{C.RESET}\n")

    print(f"  {C.DIM}Duration:{C.RESET}     {scan_time:.1f}s")
    print(f"  {C.DIM}Total Files:{C.RESET}  {len(results)}")
    print(f"  {C.GREEN}Clean:{C.RESET}        {clean_count}")

    if detected:
        print(f"  {C.RED}Threats:{C.RESET}      {len(detected)}")
        if quarantined:
            print(f"  {C.MAGENTA}Quarantined:{C.RESET}  {len(quarantined)}")

        print(f"\n  {C.RED}{C.BOLD}⚠  THREATS DETECTED:{C.RESET}\n")
        for r in detected:
            severity = max(i["severity"] for i in r["infos"])
            category = r["infos"][0]["category"]
            q_label = f" {C.MAGENTA}[QUARANTINED]{C.RESET}" if r.get("quarantined") else ""

            if severity >= 9:
                sev_color = C.BG_RED + C.WHITE
            elif severity >= 7:
                sev_color = C.RED
            else:
                sev_color = C.YELLOW

            print(f"  {sev_color}  SEV {severity:2d}  {C.RESET} {r['rel_path']}")
            ai_label = ""
            if r.get("ai_verdict"):
                v = r["ai_verdict"]
                ai_label = f" | {C.CYAN}AI: {v['reason']} ({v['confidence']}){C.RESET}"
            print(f"           {C.DIM}Category: {category} | Tags: {', '.join(r['tags'])}{q_label}{ai_label}{C.RESET}")
    else:
        print(f"\n  {C.GREEN}{C.BOLD}✓  ALL CLEAR — No threats detected!{C.RESET}")

    print(f"\n  {C.BOLD}{'═' * 55}{C.RESET}\n")

    # --- Generate report ---
    report_path = os.path.join(target_path, "usb_defender_report.json")
    if generate_report(results, target_path, scan_time, report_path):
        print(f"  {C.DIM}Report saved: {report_path}{C.RESET}\n")

    return results


# ======================================================================
# RESTORE ENGINE
# ======================================================================
def restore_quarantined(target_path):
    """List and restore quarantined files."""
    C = Colors
    quarantine_dir = os.path.join(target_path, "quarantine")

    if not os.path.exists(quarantine_dir):
        print(f"\n  {C.GREEN}No quarantine folder found. Nothing to restore.{C.RESET}\n")
        return

    # Find all .meta.json files
    meta_files = sorted(Path(quarantine_dir).glob("*.meta.json"))
    if not meta_files:
        print(f"\n  {C.GREEN}Quarantine is empty. Nothing to restore.{C.RESET}\n")
        return

    print(f"\n  {C.BOLD}{'═' * 55}{C.RESET}")
    print(f"  {C.BOLD}  QUARANTINED FILES ({len(meta_files)} total){C.RESET}")
    print(f"  {C.BOLD}{'═' * 55}{C.RESET}\n")

    items = []
    for i, mf in enumerate(meta_files):
        try:
            with open(mf, "r") as f:
                meta = json.load(f)
            items.append(meta)
            orig = meta.get("original_path", "unknown")
            tag = meta.get("tag", "unknown")
            sev = meta.get("severity", 0)
            ts = meta.get("timestamp", "unknown")
            print(f"  {C.YELLOW}[{i+1}]{C.RESET} {Path(orig).name}")
            print(f"      {C.DIM}Path: {orig}{C.RESET}")
            print(f"      {C.DIM}Tag: {tag} | Severity: {sev} | Quarantined: {ts}{C.RESET}\n")
        except Exception:
            continue

    if not items:
        print(f"  {C.RED}No valid metadata found.{C.RESET}\n")
        return

    print(f"  {C.BOLD}Options:{C.RESET}")
    print(f"  Enter a number (1-{len(items)}) to restore that file")
    print(f"  Enter 'all' to restore everything")
    print(f"  Enter 'q' to quit\n")

    choice = input(f"  {C.CYAN}>{C.RESET} ").strip().lower()

    if choice == "q":
        return
    elif choice == "all":
        indices = range(len(items))
    else:
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(items):
                indices = [idx]
            else:
                print(f"  {C.RED}Invalid number.{C.RESET}")
                return
        except ValueError:
            print(f"  {C.RED}Invalid input.{C.RESET}")
            return

    restored = 0
    for idx in indices:
        meta = items[idx]
        qpath = meta.get("quarantine_path", "")
        orig_path = meta.get("original_path", "")

        if not os.path.exists(qpath):
            print(f"  {C.RED}✗{C.RESET} Quarantine file missing: {qpath}")
            continue

        try:
            # Decrypt (XOR is symmetric)
            with open(qpath, "rb") as f:
                encrypted_data = f.read()
            original_data = xor_encrypt(encrypted_data, XOR_KEY)

            # Restore original
            os.makedirs(os.path.dirname(orig_path), exist_ok=True)
            with open(orig_path, "wb") as f:
                f.write(original_data)

            # Remove quarantine files
            os.remove(qpath)
            meta_path = qpath.replace(".qfile", ".meta.json")
            if os.path.exists(meta_path):
                os.remove(meta_path)

            print(f"  {C.GREEN}✓{C.RESET} Restored: {Path(orig_path).name}")
            restored += 1
        except Exception as e:
            print(f"  {C.RED}✗{C.RESET} Failed to restore {Path(orig_path).name}: {e}")

    print(f"\n  {C.GREEN}{restored} file(s) restored.{C.RESET}\n")


# ======================================================================
# GEMINI AI ANALYSIS (optional, zero extra dependencies)
# ======================================================================
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"


def gemini_analyze(file_path, tags, api_key, max_retries=3):
    """
    Send a suspicious file snippet to Gemini for AI-powered analysis.
    Includes retry with backoff for rate limiting.
    Returns: (is_threat: bool, explanation: str, confidence: str)
    """
    import urllib.request
    import urllib.error
    import re

    # Read first 200 lines of the file
    try:
        with open(file_path, "r", errors="ignore") as f:
            lines = f.readlines()[:200]
        snippet = "".join(lines)
        if len(snippet) > 4000:
            snippet = snippet[:4000] + "\n... (truncated)"
    except Exception:
        return True, "Could not read file for AI analysis", "low"

    filename = Path(file_path).name
    prompt = (
        f"You are a cybersecurity analyst. A USB security scanner flagged this file.\n"
        f"File: {filename}\n"
        f"Heuristic tags: {', '.join(tags)}\n"
        f"File content (first 200 lines):\n```\n{snippet}\n```\n\n"
        f"Is this file actually malicious or is it a false positive (e.g. a normal "
        f"development file, npm package, or legitimate script)?\n"
        f"Respond with JSON only: "
        f'{{"is_threat": true, "confidence": "high", "reason": "explanation"}}'
    )

    payload = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.1,
            "maxOutputTokens": 1000,
            "responseMimeType": "application/json",
        }
    }).encode("utf-8")

    url = f"{GEMINI_API_URL}?key={api_key}"

    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(url, data=payload, method="POST",
                                         headers={"Content-Type": "application/json"})

            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read().decode("utf-8"))

            text = result["candidates"][0]["content"]["parts"][0]["text"].strip()

            # Try direct JSON parse first (responseMimeType should give clean JSON)
            try:
                analysis = json.loads(text)
            except json.JSONDecodeError:
                # Fallback: extract JSON object from response with regex
                match = re.search(r'\{[^{}]*"is_threat"[^{}]*\}', text)
                if match:
                    analysis = json.loads(match.group(0))
                else:
                    # Last resort: use the raw text as the reason
                    clean = re.sub(r'[`\n]', ' ', text).strip()[:200]
                    return True, clean if clean else "AI returned unparseable response", "medium"

            return (
                analysis.get("is_threat", True),
                analysis.get("reason", "No explanation"),
                analysis.get("confidence", "medium"),
            )

        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < max_retries - 1:
                wait = (attempt + 1) * 5  # 5s, 10s, 15s
                time.sleep(wait)
                continue
            return True, f"API error (HTTP {e.code})", "low"
        except Exception as e:
            return True, f"AI unavailable ({type(e).__name__})", "low"

    return True, "AI rate limited after retries", "low"


def validate_gemini_key(api_key):
    """Validate the Gemini API key format (no API call to save rate limit)."""
    C = Colors

    if not api_key or len(api_key) < 20:
        print(f"  {C.RED}✗ API key is too short{C.RESET}")
        return False

    if not api_key.startswith("AIza"):
        print(f"  {C.RED}✗ Invalid API key format (should start with AIza...){C.RESET}")
        return False

    print(f"  {C.GREEN}✓ Gemini API key accepted{C.RESET}")
    return True


# ======================================================================
# ENTRY POINT
# ======================================================================
def main():
    Colors.enable()
    C = Colors

    parser = argparse.ArgumentParser(
        description="USB Defender Portable Scanner — Zero-dependency USB security."
    )
    parser.add_argument(
        "--path", "-p",
        help="Path to scan. If omitted, auto-detects USB root from script location.",
        default=None,
    )
    parser.add_argument(
        "--no-quarantine",
        action="store_true",
        help="Report threats only, do not quarantine.",
    )
    parser.add_argument(
        "--restore",
        action="store_true",
        help="Restore quarantined files instead of scanning.",
    )
    parser.add_argument(
        "--ai-key",
        type=str,
        default=None,
        help="Gemini API key for AI-powered threat verification (optional, free).",
    )
    args = parser.parse_args()

    print_banner()

    # Determine target
    if args.path:
        target = Path(args.path).resolve()
    else:
        target = get_usb_root()

    if not target.exists():
        print(f"\n  {C.RED}ERROR: Target path does not exist: {target}{C.RESET}")
        sys.exit(1)

    # Restore mode
    if args.restore:
        print(f"  {C.BOLD}Target:{C.RESET}   {target}")
        print(f"  {C.BOLD}Mode:{C.RESET}     Restore Quarantined Files")
        restore_quarantined(str(target))
        sys.exit(0)

    # Load AI key from config if not provided
    ai_key = args.ai_key
    config_path = os.path.join(str(target), ".usb_defender_config.json")
    if not ai_key and os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                config = json.load(f)
            ai_key = config.get("gemini_api_key")
        except Exception:
            pass

    # Save AI key to config for next time
    if args.ai_key:
        try:
            config = {}
            if os.path.exists(config_path):
                with open(config_path, "r") as f:
                    config = json.load(f)
            config["gemini_api_key"] = args.ai_key
            with open(config_path, "w") as f:
                json.dump(config, f, indent=4)
        except Exception:
            pass

    # Validate AI key if provided
    if ai_key:
        if not validate_gemini_key(ai_key):
            print(f"  {C.YELLOW}  Falling back to heuristic-only mode.{C.RESET}\n")
            ai_key = None

    ai_label = f"AI-Verified (Gemini)" if ai_key else "Heuristic Only"
    print(f"  {C.BOLD}Target:{C.RESET}   {target}")
    print(f"  {C.BOLD}Platform:{C.RESET} {platform.system()} {platform.release()}")
    print(f"  {C.BOLD}Mode:{C.RESET}     {'Report Only' if args.no_quarantine else 'Scan & Quarantine'}")
    print(f"  {C.BOLD}Analysis:{C.RESET} {ai_label}")

    do_quarantine = not args.no_quarantine

    try:
        results = run_scan(str(target), do_quarantine, ai_key)
        detected = [r for r in results if r["detected"]]
        sys.exit(1 if detected else 0)
    except KeyboardInterrupt:
        print(f"\n\n  {C.YELLOW}Scan cancelled by user.{C.RESET}\n")
        sys.exit(130)


if __name__ == "__main__":
    main()


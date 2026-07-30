#!/usr/bin/env python3
"""
signatures.py
--------------
Unified malware signature + heuristic rule engine.
Supports:
- JSON-based signatures (rules + hashes), user-editable and persisted
- Python-side known hashes (KNOWN_BAD_HASHES)
- File size limits for hashing and heuristics (OOM protection)
- Multi-tag detection (returns ALL matches)
- Two-tier patterns to suppress false positives

Rule confidence model
---------------------
``strong_patterns`` are literal indicators that are conclusive on their own
(``invoke-webrequest``, ``vssadmin delete shadows``). A single hit flags
the file.

``regex_patterns`` express structure that plain substrings cannot — for
example "a forced delete aimed at an absolute drive path". Also conclusive
on a single hit.

``patterns`` are weak keywords that only mean something in combination
(``import os``, ``del /f``). These require ``MIN_PATTERN_MATCHES`` distinct
hits. This is the difference between a scanner that finds droppers and one
that encrypts every Python file on the drive.

This rule set is deliberately kept in sync with the embedded copy in
``portable/usb_defender_portable.py`` — the two engines must agree, or the
same drive gets different verdicts from the desktop app and the portable
scanner.
"""

import json
import os
import re
import shutil
from pathlib import Path

from db import compute_sha256
from paths import get_bundle_dir, get_data_dir

# ==============================
# Paths
# ==============================
# Read-only defaults ship with the bundle; the live, user-editable copy
# lives in the writable data dir so edits survive a restart.
BUNDLED_SIGNATURE_FILE = get_bundle_dir() / "signatures.json"
SIGNATURE_FILE = get_data_dir() / "signatures.json"

# ==============================
# OOM Protection
# ==============================
MAX_HEURISTIC_SIZE = 5 * 1024 * 1024   # 5 MB — skip heuristic reads above this
MAX_HASH_SIZE = 100 * 1024 * 1024      # 100 MB — skip SHA256 above this

# ==============================
# False-positive suppression
# ==============================
MIN_PATTERN_MATCHES = 2

# Directories that are developer/system noise, never a USB threat vector.
SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    ".svn", ".hg", "bower_components", ".tox", ".eggs",
    "System Volume Information", "$RECYCLE.BIN",
    ".Trash", ".Trashes", ".Spotlight-V100", ".fseventsd",
    "quarantine",
}

# Extensions with no script-injection surface. Skipping them is a large
# speed win and removes a whole class of false positives on binary blobs.
SKIP_EXTENSIONS = {
    ".iso", ".img", ".vmdk", ".vdi", ".vhd", ".ova",      # Disk images
    ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv",       # Video
    ".mp3", ".flac", ".wav", ".aac", ".ogg", ".wma",      # Audio
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",  # Archives
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp",     # Images
    ".pdf",                                               # Documents
    ".ttf", ".otf", ".woff", ".woff2",                    # Fonts
    ".so", ".dylib",                                      # Shared libs
    ".qfile",                                             # Already quarantined
}

# ==============================
# Python Hardcoded Known Hashes
# ==============================
KNOWN_BAD_HASHES = {
    # Standard EICAR MD5 (commonly used)
    "44d88612fea8a8f36de82e1278abb02f": "EICAR_MD5",

    # Standard EICAR SHA256
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR_SHA256",

    # Extra dummy examples
    "fe42dcc3454c3193434b4ee6029c9b898d8f48765b3fc547ac38c009b91a3b8a": "Test_EICAR_Dummy_File",
}

# Tags produced by exact-hash matching. These are certainties — the AI
# verification pass in the portable scanner must never override them.
HASH_TAGS = set(KNOWN_BAD_HASHES.values()) | {"Known_Malware_Hash"}

# ==============================
# Default JSON signatures
# ==============================
DEFAULT_SIGNATURES = {
    "malware_hashes": [
        # SHA256 EICAR test file
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    ],
    "rules": [
        {
            "name": "Suspicious_HTML_Executable",
            # .txt removed: a plain-text file merely mentioning "powershell"
            # was scoring severity 8 and getting quarantined.
            "extensions": [".html", ".htm", ".hta"],
            "strong_patterns": [
                "<script>powershell", "<script>cmd.exe", "<script>bitsadmin",
                "wscript.shell", "activexobject", "eval(atob(",
                "document.write(unescape("
            ],
            "patterns": ["<script>", "powershell", "cmd.exe", "base64,"]
        },
        {
            "name": "Potential_Malicious_Python",
            "extensions": [".py", ".pyw"],
            "strong_patterns": ["pty.spawn", "eval(compile(", "__import__('os')"],
            "patterns": [
                "exec(", "eval(", "subprocess", "socket.socket",
                "os.system", "base64.b64decode"
            ]
        },
        {
            "name": "Suspicious_Batch_Script",
            "extensions": [".bat", ".cmd"],
            "strong_patterns": [
                "vssadmin delete shadows", "bcdedit /set", "format c:"
            ],
            # A forced/recursive delete pointed at an absolute drive path is
            # destructive regardless of which flags are used or their order.
            "regex_patterns": [
                r"del\s+(?:/[a-z]\s+)*[a-z]:\\",
                r"rmdir\s+/s",
                r"format\s+[a-z]:",
                r"reg\s+delete\s+hk"
            ],
            "patterns": [
                "del /f", "del /s", "del /q", "format ", "net user",
                "reg add", "reg delete", "taskkill", "attrib +h"
            ]
        },
        {
            "name": "Suspicious_PowerShell_Script",
            "extensions": [".ps1", ".psm1"],
            "strong_patterns": [
                "invoke-webrequest", "downloadstring", "-encodedcommand",
                "frombase64string", "invoke-expression",
                "new-object net.webclient", "-executionpolicy bypass"
            ],
            "patterns": ["iex", "-windowstyle hidden", "start-process", "net.webclient"]
        },
        {
            "name": "Suspicious_VBS_Script",
            "extensions": [".vbs", ".vbe", ".js", ".jse", ".wsf"],
            "strong_patterns": ["wscript.shell", "adodb.stream", "activexobject"],
            "patterns": ["createobject", "shell.application", ".run "]
        },
        {
            "name": "Suspicious_Shell_Script",
            "extensions": [".sh", ".bash", ".zsh"],
            "strong_patterns": ["/dev/tcp/"],
            # Pipe-to-shell in any of its spellings: curl … | sh, wget … | bash -s
            "regex_patterns": [
                r"(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z|d)?sh\b"
            ],
            "patterns": [
                "curl ", "wget ", "| sh", "| bash", "chmod +x",
                "nohup ", "base64 -d"
            ]
        }
    ]
}

# ==============================
# Signature cache (avoid re-reading JSON every call)
# ==============================
_cached_signatures = None


def ensure_signatures():
    """
    Guarantee a writable signatures.json exists in the data dir, seeding it
    from the bundled copy (or the built-in defaults) on first run.
    """
    if SIGNATURE_FILE.exists():
        return

    SIGNATURE_FILE.parent.mkdir(parents=True, exist_ok=True)

    if BUNDLED_SIGNATURE_FILE.exists() and BUNDLED_SIGNATURE_FILE != SIGNATURE_FILE:
        try:
            shutil.copyfile(BUNDLED_SIGNATURE_FILE, SIGNATURE_FILE)
            return
        except OSError:
            pass

    with open(SIGNATURE_FILE, "w", encoding="utf-8") as f:
        json.dump(DEFAULT_SIGNATURES, f, indent=4)


def load_signatures():
    global _cached_signatures
    if _cached_signatures is not None:
        return _cached_signatures

    ensure_signatures()
    try:
        with open(SIGNATURE_FILE, "r", encoding="utf-8") as f:
            _cached_signatures = json.load(f)
    except (OSError, json.JSONDecodeError):
        # A corrupted or hand-edited file must not take the engine down.
        _cached_signatures = DEFAULT_SIGNATURES
    return _cached_signatures


def reload_signatures():
    """Force reload of signatures from disk (e.g. after user edits signatures.json)."""
    global _cached_signatures
    _cached_signatures = None
    return load_signatures()


def save_signatures(payload: dict) -> None:
    """
    Persist a new ruleset and refresh the cache.

    Writes via a temp file and os.replace so an interrupted save cannot leave
    a truncated ruleset behind — a half-written signatures.json would make
    the engine fall back to defaults with no warning.

    This module owns the path deliberately: callers that captured
    SIGNATURE_FILE at import time would write somewhere else entirely once
    the location is reconfigured.
    """
    SIGNATURE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = SIGNATURE_FILE.with_suffix(".json.tmp")

    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=4)
    os.replace(tmp, SIGNATURE_FILE)

    reload_signatures()


def should_skip_path(file_path: str) -> bool:
    """True when a file is excluded from scanning by directory or extension."""
    p = Path(file_path)
    if p.suffix.lower() in SKIP_EXTENSIONS:
        return True
    return any(part in SKIP_DIRS for part in p.parts)


_regex_cache: dict[str, "re.Pattern | None"] = {}


def _compiled(pattern: str):
    """Compile and memoize a rule regex; a bad pattern is ignored, not fatal."""
    if pattern not in _regex_cache:
        try:
            _regex_cache[pattern] = re.compile(pattern, re.IGNORECASE)
        except re.error:
            _regex_cache[pattern] = None
    return _regex_cache[pattern]


def _rule_matches(rule: dict, content: str) -> bool:
    """
    Apply one rule's confidence tiers to already-lowercased content.
    """
    for pattern in rule.get("strong_patterns", []):
        if pattern.lower() in content:
            return True

    for pattern in rule.get("regex_patterns", []):
        compiled = _compiled(pattern)
        if compiled is not None and compiled.search(content):
            return True

    patterns = rule.get("patterns", [])
    if not patterns:
        return False

    matched = sum(1 for p in patterns if p.lower() in content)
    # A rule with a single weak pattern would otherwise be unsatisfiable.
    threshold = min(MIN_PATTERN_MATCHES, len(patterns))
    return matched >= threshold


# ==============================
# MATCH FILE AGAINST SIGNATURES
# ==============================
def match_file(file_path: str):
    """
    Scan a file against all signature/heuristic rules.
    Returns: (is_suspicious: bool, tags: list[str])
    If clean, returns (False, [])
    """
    sigs = load_signatures()
    tags = []

    if should_skip_path(file_path):
        return False, []

    ext = Path(file_path).suffix.lower()

    try:
        file_size = os.path.getsize(file_path)
    except OSError:
        return False, []

    # -------------------------------
    # 1. Hash-based detection (exact match — always authoritative)
    # -------------------------------
    if 0 < file_size <= MAX_HASH_SIZE:
        sha256 = compute_sha256(file_path)

        if sha256 and sha256 in KNOWN_BAD_HASHES:
            tags.append(KNOWN_BAD_HASHES[sha256])

        if sha256 and sha256 in sigs.get("malware_hashes", []):
            if "Known_Malware_Hash" not in tags:
                tags.append("Known_Malware_Hash")

    # -------------------------------
    # 2. Heuristic scanning (with OOM protection)
    # -------------------------------
    if 0 < file_size <= MAX_HEURISTIC_SIZE:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read().lower()

            for rule in sigs.get("rules", []):
                if ext not in rule.get("extensions", []):
                    continue
                if _rule_matches(rule, content):
                    rule_name = rule.get("name")
                    if rule_name and rule_name not in tags:
                        tags.append(rule_name)

        except Exception:
            pass

    # -------------------------------
    # Result
    # -------------------------------
    if tags:
        return True, tags
    return False, []

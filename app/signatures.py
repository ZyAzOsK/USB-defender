#!/usr/bin/env python3
"""
signatures.py
--------------
Unified malware signature + heuristic rule engine.
Supports:
- JSON-based signatures (rules + hashes)
- Python-side known hashes (KNOWN_BAD_HASHES)
- HTML/script special-case scanning
- File size limit for heuristic scanning (OOM protection)
- Multi-tag detection (returns ALL matches)
"""

import json
import os
from pathlib import Path
from db import compute_sha256

# ==============================
# Paths
# ==============================
SIGNATURE_FILE = Path(__file__).resolve().parent / "signatures.json"

# ==============================
# OOM Protection
# ==============================
MAX_HEURISTIC_SIZE = 5 * 1024 * 1024  # 5 MB — skip heuristic reads for larger files

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

# ==============================
# HTML/Script Quick Heuristics
# ==============================
HTML_SCRIPT_PATTERNS = [
    ("<script>powershell", "Suspicious_HTML_Executable"),
    ("<script>cmd.exe", "Suspicious_HTML_Executable"),
    ("<script>bitsadmin", "Suspicious_HTML_Executable"),
    ("<script>wscript.shell", "Suspicious_HTML_Executable"),
]

# ==============================
# Ensure JSON signatures exists
# ==============================
DEFAULT_SIGNATURES = {
    "malware_hashes": [
        # SHA256 EICAR test file
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    ],
    "rules": [
        {
            "name": "Suspicious_HTML_Executable",
            "patterns": ["<script>", "powershell", "cmd.exe", "base64,"],
            "extensions": [".html", ".htm", ".txt"]
        },
        {
            "name": "Potential_Malicious_Python",
            "patterns": ["import os", "exec(", "subprocess", "socket"],
            "extensions": [".py"]
        },
        {
            "name": "Suspicious_Batch_Script",
            "patterns": ["del /f", "format ", "net user", "reg add", "reg delete", "taskkill"],
            "extensions": [".bat", ".cmd"]
        },
        {
            "name": "Suspicious_PowerShell_Script",
            "patterns": ["invoke-webrequest", "iex", "downloadstring", "-encodedcommand",
                         "invoke-expression", "new-object net.webclient"],
            "extensions": [".ps1"]
        },
        {
            "name": "Suspicious_VBS_Script",
            "patterns": ["wscript.shell", "createobject", "activexobject", "shell.application"],
            "extensions": [".vbs", ".js", ".wsf"]
        }
    ]
}

# ==============================
# Signature cache (avoid re-reading JSON every call)
# ==============================
_cached_signatures = None


def ensure_signatures():
    if not SIGNATURE_FILE.exists():
        with open(SIGNATURE_FILE, "w") as f:
            json.dump(DEFAULT_SIGNATURES, f, indent=4)


def load_signatures():
    global _cached_signatures
    if _cached_signatures is not None:
        return _cached_signatures

    ensure_signatures()
    with open(SIGNATURE_FILE, "r") as f:
        _cached_signatures = json.load(f)
    return _cached_signatures


def reload_signatures():
    """Force reload of signatures from disk (e.g. after user edits signatures.json)."""
    global _cached_signatures
    _cached_signatures = None
    return load_signatures()


# ==============================
# MATCH FILE AGAINST SIGNATURES
# Returns list of (tag, match_type) tuples
# ==============================
def match_file(file_path: str):
    """
    Scan a file against all signature/heuristic rules.
    Returns: (is_suspicious: bool, tags: list[str])
    If clean, returns (False, [])
    """
    sigs = load_signatures()
    tags = []

    sha256 = compute_sha256(file_path)
    ext = Path(file_path).suffix.lower()

    # -------------------------------
    # 1. Python-side known bad hashes
    # -------------------------------
    if sha256 and sha256 in KNOWN_BAD_HASHES:
        tags.append(KNOWN_BAD_HASHES[sha256])

    # -------------------------------
    # 2. JSON malware_hashes
    # -------------------------------
    if sha256 and sha256 in sigs.get("malware_hashes", []):
        if "Known_Malware_Hash" not in tags:
            tags.append("Known_Malware_Hash")

    # -------------------------------
    # 3. Heuristic scanning (with OOM protection)
    #    Single file read for both HTML patterns and JSON rules
    # -------------------------------
    try:
        file_size = os.path.getsize(file_path)
    except OSError:
        file_size = 0

    if file_size <= MAX_HEURISTIC_SIZE and file_size > 0:
        try:
            with open(file_path, "r", errors="ignore") as f:
                content = f.read().lower()

            # 3a. HTML/script quick heuristics
            for pattern, tag in HTML_SCRIPT_PATTERNS:
                if pattern in content:
                    if tag not in tags:
                        tags.append(tag)

            # 3b. JSON heuristic rule matching
            for rule in sigs.get("rules", []):
                if ext in rule.get("extensions", []):
                    if any(p.lower() in content for p in rule.get("patterns", [])):
                        rule_name = rule["name"]
                        if rule_name not in tags:
                            tags.append(rule_name)

        except Exception:
            pass

    # -------------------------------
    # Result
    # -------------------------------
    if tags:
        return True, tags
    return False, []

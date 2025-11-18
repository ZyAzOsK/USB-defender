#!/usr/bin/env python3
"""
signatures.py
--------------
Unified malware signature + heuristic rule engine.
Now supports:
- JSON-based signatures
- Python-side known hashes (KNOWN_BAD_HASHES)
- HTML/script special-case scanning
- .txt injection detection
"""

import json
import hashlib
from pathlib import Path

# ==============================
# Paths
# ==============================
SIGNATURE_FILE = Path(__file__).resolve().parent / "signatures.json"

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
        }
    ]
}


def ensure_signatures():
    if not SIGNATURE_FILE.exists():
        with open(SIGNATURE_FILE, "w") as f:
            json.dump(DEFAULT_SIGNATURES, f, indent=4)


def load_signatures():
    ensure_signatures()
    with open(SIGNATURE_FILE, "r") as f:
        return json.load(f)


# ==============================
# Compute SHA256 for scanning
# ==============================
def compute_sha256(path: str):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


# ==============================
# MATCH FILE AGAINST SIGNATURES
# ==============================
def match_file(file_path: str):
    sigs = load_signatures()

    sha256 = compute_sha256(file_path)
    ext = Path(file_path).suffix.lower()

    # -------------------------------
    # 1. Python-side known bad hashes
    # -------------------------------
    if sha256 in KNOWN_BAD_HASHES:
        return True, KNOWN_BAD_HASHES[sha256]

    # -------------------------------
    # 2. JSON malware_hashes
    # -------------------------------
    if sha256 in sigs["malware_hashes"]:
        return True, "Known_Malware_Hash"

    # -------------------------------
    # 3. HTML/script quick heuristics
    # -------------------------------
    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read().lower()

        for pattern, tag in HTML_SCRIPT_PATTERNS:
            if pattern in content:
                return True, tag
    except Exception:
        pass

    # -------------------------------
    # 4. JSON Heuristic Rule Matching
    # -------------------------------
    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read().lower()

        for rule in sigs["rules"]:
            if ext in rule["extensions"]:
                if any(p in content for p in rule["patterns"]):
                    return True, rule["name"]
    except Exception:
        pass

    # -------------------------------
    # 5. Clean
    # -------------------------------
    return False, None

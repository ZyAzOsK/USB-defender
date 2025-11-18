#!/usr/bin/env python3
"""
signatures.py
--------------
Handles malware and heuristic signature management for USB Defender.
Supports:
- Known malware hashes
- Simple pattern-based heuristic rules
- JSON persistence for future updates
"""

import json
import hashlib
from pathlib import Path

# --- File paths ---
SIGNATURE_FILE = Path(__file__).resolve().parent / "signatures.json"

# --- Default built-in signatures (auto-written if missing) ---
DEFAULT_SIGNATURES = {
    "malware_hashes": [
        # SHA256 hashes of known or test malware (e.g., EICAR)
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    ],
    "rules": [
        {
            "name": "Suspicious_HTML_Executable",
            "patterns": ["<script>", "base64,", "powershell", "cmd.exe"],
            "extensions": [".html", ".htm", ".txt"]
        },
        {
            "name": "Potential_Malicious_Python",
            "patterns": ["import os", "exec(", "subprocess", "socket"],
            "extensions": [".py"]
        }
    ]
}
# List of known malicious file hashes — SHA256 for example

KNOWN_BAD_HASHES = {
    # Example known-bad samples
    "44d88612fea8a8f36de82e1278abb02f": "EICAR_Test_File",
    "fe42dcc3454c3193434b4ee6029c9b898d8f48765b3fc547ac38c009b91a3b8a": "Test_EICAR_Dummy_File",
    "e2fc714c4727ee9395f324cd2e7f331f": "Sample_Malware",
}

# HTML/Script-based threat signatures
HTML_SCRIPT_PATTERNS = [
    ("<script>powershell", "Suspicious_HTML_Executable"),
    ("<script>cmd.exe", "Suspicious_HTML_Executable"),
    ("<script>bitsadmin", "Suspicious_HTML_Executable"),
    ("<script>wscript.shell", "Suspicious_HTML_Executable"),
]

# --- Ensure signatures file exists ---
def ensure_signatures():
    """Creates a default signatures.json if not found."""
    if not SIGNATURE_FILE.exists():
        with open(SIGNATURE_FILE, "w") as f:
            json.dump(DEFAULT_SIGNATURES, f, indent=4)

# --- Load signatures into memory ---
def load_signatures():
    ensure_signatures()
    with open(SIGNATURE_FILE, "r") as f:
        return json.load(f)

# --- Hash utility ---
def compute_sha256(file_path: str):
    try:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

# --- Matching logic ---
def match_file(file_path: str):
    """
    Scans a file against loaded signatures.
    Returns (bool, tag) where:
      bool → True if suspicious/malicious
      tag  → descriptive signature name
    """
    sigs = load_signatures()
    sha256 = compute_sha256(file_path)

    # --- 1. Hash-based detection ---
    if sha256 and sha256 in sigs["malware_hashes"]:
        return True, "Known_Malware_Hash"

    # --- 2. Heuristic content-based detection ---
    ext = Path(file_path).suffix.lower()
    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read().lower()
        for rule in sigs["rules"]:
            if ext in rule["extensions"]:
                if any(pat in content for pat in rule["patterns"]):
                    return True, rule["name"]
    except Exception:
        pass

    return False, None

# app/detector.py

import hashlib
import os
from signatures import KNOWN_BAD_HASHES, HTML_SCRIPT_PATTERNS

def compute_file_hash(file_path):
    """Compute SHA256 hash of a given file."""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"[ERROR] Failed to hash {file_path}: {e}")
        return None


def detect_threat(file_path):
    """
    Detect potential threats in the given file using:
      - Known malicious hash matching
      - HTML/script pattern matching
    """
    findings = []

    # Step 1: Hash-based threat detection
    file_hash = compute_file_hash(file_path)
    if file_hash in KNOWN_BAD_HASHES:
        findings.append({
            "file": os.path.basename(file_path),
            "tag": "Known_Malware_Hash",
            "description": KNOWN_BAD_HASHES[file_hash],
        })

    # Step 2: Suspicious HTML/Script detection
    if file_path.lower().endswith(".html") or file_path.lower().endswith(".htm"):
        try:
            with open(file_path, "r", errors="ignore") as f:
                content = f.read().lower()
            for pattern, tag in HTML_SCRIPT_PATTERNS:
                if pattern in content:
                    findings.append({
                        "file": os.path.basename(file_path),
                        "tag": tag,
                        "description": f"Pattern '{pattern}' found in HTML",
                    })
        except Exception as e:
            print(f"[ERROR] Could not analyze HTML file: {e}")

    return findings

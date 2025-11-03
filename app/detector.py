# app/detector.py
import os
import re
import hashlib
from signatures import KNOWN_BAD_HASHES

def compute_sha256(file_path):
    """Compute SHA256 hash of a file safely."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None


def check_file_hash(file_path):
    """Return a tag if file hash matches a known malicious one."""
    file_hash = compute_sha256(file_path)
    if file_hash and file_hash in KNOWN_BAD_HASHES:
        return f"KNOWN_BAD: {KNOWN_BAD_HASHES[file_hash]}"
    return None


def check_file_content(file_path):
    """Perform lightweight pattern-based detection for suspicious content."""
    try:
        if not os.path.exists(file_path) or os.path.getsize(file_path) > 5 * 1024 * 1024:
            # Skip large files (>5 MB)
            return None

        with open(file_path, "r", errors="ignore") as f:
            content = f.read().lower()

        # Pattern-based rules
        if re.search(r"<script>.*powershell.*</script>", content, re.DOTALL):
            return "Suspicious_HTML_Executable"

        if re.search(r"cmd\.exe|wscript\.shell|vbscript", content):
            return "Windows_Script_Abuse"

        if re.search(r"base64\s*\(", content):
            return "Encoded_Payload"

    except Exception:
        pass

    return None


def detect_threat(file_path):
    """
    Combined detection: hash + content
    Returns tag string if threat is detected.
    """
    tag = check_file_hash(file_path)
    if tag:
        return tag

    tag = check_file_content(file_path)
    if tag:
        return tag

    return None

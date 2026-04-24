#!/usr/bin/env python3
"""
scanner.py
-----------
One-time recursive USB file scanner.
Features:
- Symlink protection (followlinks=False)
- Concurrent scanning with ThreadPoolExecutor
- Multi-tag detection support
"""

import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from signatures import match_file
from threat_intel import enrich_tag
from logger import log_event
from quarantine import quarantine_file

# Max parallel scan workers
MAX_WORKERS = 4


def _scan_single_file(file_path, target_path):
    """Scan a single file and return the result dict."""
    rel_path = os.path.relpath(file_path, target_path)

    is_suspicious, tags = match_file(file_path)

    if not is_suspicious:
        info = enrich_tag("Clean")
        status = "CLEAN"
        log_event(event_type="Scan", file_path=file_path, info=info)
        return {"rel_path": rel_path, "status": status, "detected": False, "infos": [info]}
    else:
        infos = []
        status_parts = []
        for tag in tags:
            info = enrich_tag(tag)
            infos.append(info)
            status_parts.append(f"⚠️  {info['category']} (Severity {info['severity']})")
            log_event(event_type="Scan", file_path=file_path, info=info)
            
            # Auto-quarantine during scan if the file still exists
            if os.path.exists(file_path):
                quarantine_dir = os.path.join(target_path, "quarantine")
                quarantine_file(file_path, info, quarantine_dir)
                
        status = " | ".join(status_parts)
        return {"rel_path": rel_path, "status": status, "detected": True, "infos": infos}


def scan_target(target_path):
    """
    Scans the given target directory recursively for suspicious or malicious files.
    Uses thread pool for concurrent scanning.
    Returns a summary dict with clean and detected file counts.
    """
    detected = 0
    clean = 0

    print(f"\n🔍 Scanning target: {target_path}\n")

    # Collect all file paths first (symlink-safe)
    file_paths = []
    for root, dirs, files in os.walk(target_path, followlinks=False):
        # Skip quarantine directory
        if "quarantine" in dirs:
            dirs.remove("quarantine")
        for filename in files:
            file_path = os.path.join(root, filename)
            # Skip symlinks
            if os.path.islink(file_path):
                rel = os.path.relpath(file_path, target_path)
                print(f"{rel} → ⏭ SKIPPED (symlink)")
                continue
            file_paths.append(file_path)

    # Scan concurrently
    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_path = {
            executor.submit(_scan_single_file, fp, target_path): fp
            for fp in file_paths
        }

        for future in as_completed(future_to_path):
            try:
                result = future.result()
                results.append(result)
                if result["detected"]:
                    detected += 1
                else:
                    clean += 1
                print(f"{result['rel_path']} → {result['status']}")
            except Exception as e:
                fp = future_to_path[future]
                print(f"{os.path.relpath(fp, target_path)} → ❌ ERROR: {e}")

    print("\n--- Scan Complete ---")
    print(f"Total Files: {detected + clean}")
    print(f"Detected: {detected}")
    print(f"Clean: {clean}")

    return {"detected": detected, "clean": clean}

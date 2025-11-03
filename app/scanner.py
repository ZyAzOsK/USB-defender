#!/usr/bin/env python3
"""
scanner.py
-----------
Scans USB files for known malware and heuristic patterns.
Integrates with threat intelligence enrichment.
"""

import os
from pathlib import Path
from signatures import match_file
from threat_intel import enrich_tag
from logger import log_event


def scan_target(target_path):
    """
    Scans the given target directory recursively for suspicious or malicious files.
    Returns a summary dict with clean and detected file counts.
    """
    detected = 0
    clean = 0

    print(f"\n🔍 Scanning target: {target_path}\n")

    for root, _, files in os.walk(target_path):
        for filename in files:
            file_path = os.path.join(root, filename)
            rel_path = os.path.relpath(file_path, target_path)

            # --- Check if file matches any known signature ---
            is_suspicious, tag = match_file(file_path)

            if not is_suspicious:
                # Even clean files are enriched (for logging consistency)
                info = enrich_tag("Clean")
                status = "CLEAN"
                clean += 1
            else:
                # Enrich the detected threat tag
                info = enrich_tag(tag)
                status = f"⚠️  {info['category']} (Severity {info['severity']})"
                detected += 1

            # Log result to database
            log_event(
                event_type="Scan",
                file_path=file_path,
                info=info
            )

            print(f"{rel_path} → {status}")

    print("\n--- Scan Complete ---")
    print(f"Total Files: {detected + clean}")
    print(f"Detected: {detected}")
    print(f"Clean: {clean}")

    return {"detected": detected, "clean": clean}

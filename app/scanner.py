#!/usr/bin/env python3
"""
scanner.py
-----------
One-time recursive file scanner.
Features:
- Symlink protection (followlinks=False)
- Concurrent scanning with ThreadPoolExecutor
- Multi-tag detection support
- Quarantine gated on severity, matching watcher.py and the portable engine
- Skips developer/system directories to avoid false positives
"""

import os
from concurrent.futures import ThreadPoolExecutor, as_completed

from signatures import match_file, SKIP_DIRS, should_skip_path
from threat_intel import enrich_tag
from logger import log_event
from quarantine import quarantine_file
from paths import get_data_dir

# Max parallel scan workers
MAX_WORKERS = 4

# Only neutralize high-confidence, high-impact findings. Anything lower is
# reported and logged but left alone — quarantine deletes the original, so
# acting on a severity-7 heuristic hit means destroying user data on a guess.
# Kept identical to watcher.QUARANTINE_SEVERITY_THRESHOLD and the portable
# scanner's threshold.
QUARANTINE_SEVERITY_THRESHOLD = 8


def _resolve_quarantine_dir(target_path: str) -> str:
    """
    Prefer a quarantine folder on the scanned volume, so a USB drive carries
    its own vault. Fall back to the app data dir when the target is
    read-only (write-protected sticks, mounted images).
    """
    candidate = os.path.join(target_path, "quarantine")
    try:
        os.makedirs(candidate, exist_ok=True)
        probe = os.path.join(candidate, ".write-test")
        with open(probe, "w") as f:
            f.write("")
        os.remove(probe)
        return candidate
    except OSError:
        fallback = get_data_dir() / "quarantine"
        fallback.mkdir(parents=True, exist_ok=True)
        return str(fallback)


def _scan_single_file(file_path, target_path, quarantine_dir):
    """Scan a single file and return the result dict."""
    rel_path = os.path.relpath(file_path, target_path)

    is_suspicious, tags = match_file(file_path)

    if not is_suspicious:
        info = enrich_tag("Clean")
        log_event(event_type="Scan", file_path=file_path, info=info)
        return {"rel_path": rel_path, "status": "CLEAN", "detected": False,
                "infos": [info], "quarantined": False}

    infos = [enrich_tag(tag) for tag in tags]
    max_severity = max(i["severity"] for i in infos)

    # Quarantine at most once per file, before logging, so the log records
    # the outcome. Looping per tag used to call quarantine repeatedly and
    # every call after the first failed on the already-deleted original.
    quarantine_path = None
    if max_severity >= QUARANTINE_SEVERITY_THRESHOLD and os.path.exists(file_path):
        worst = max(infos, key=lambda i: i["severity"])
        quarantine_path = quarantine_file(file_path, worst, quarantine_dir)
    quarantined = quarantine_path is not None

    status_parts = []
    for info in infos:
        if quarantined:
            info = {**info, "quarantine_path": quarantine_path}
        status_parts.append(f"⚠️  {info['category']} (Severity {info['severity']})")
        log_event(event_type="Scan", file_path=file_path, info=info)

    if quarantined:
        status_parts.append("[QUARANTINED]")

    return {"rel_path": rel_path, "status": " | ".join(status_parts),
            "detected": True, "infos": infos, "quarantined": quarantined}


def _collect_files(target_path):
    """Walk the target, skipping symlinks, skip-dirs and skip-extensions."""
    file_paths = []
    for root, dirs, files in os.walk(target_path, followlinks=False):
        # Prune noise directories in place so os.walk never descends them.
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for filename in files:
            file_path = os.path.join(root, filename)
            if os.path.islink(file_path):
                continue
            if should_skip_path(file_path):
                continue
            file_paths.append(file_path)
    return file_paths


def scan_target(target_path):
    """
    Scans the given target directory recursively for suspicious or malicious files.
    Uses a thread pool for concurrent scanning.
    Returns a summary dict with clean, detected and quarantined counts.
    """
    detected = 0
    clean = 0
    quarantined = 0
    errors = 0

    print(f"\n🔍 Scanning target: {target_path}\n", flush=True)

    quarantine_dir = _resolve_quarantine_dir(target_path)
    file_paths = _collect_files(target_path)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_path = {
            executor.submit(_scan_single_file, fp, target_path, quarantine_dir): fp
            for fp in file_paths
        }

        for future in as_completed(future_to_path):
            fp = future_to_path[future]
            try:
                result = future.result()
                if result["detected"]:
                    detected += 1
                    if result["quarantined"]:
                        quarantined += 1
                else:
                    clean += 1
                print(f"{result['rel_path']} → {result['status']}", flush=True)
            except Exception as e:
                errors += 1
                print(f"{os.path.relpath(fp, target_path)} → ❌ ERROR: {e}", flush=True)

    print("\n--- Scan Complete ---")
    print(f"Total Files: {detected + clean}")
    print(f"Detected: {detected}")
    print(f"Quarantined: {quarantined}")
    print(f"Clean: {clean}")
    if errors:
        print(f"Errors: {errors}")
    print("", flush=True)

    return {
        "detected": detected,
        "clean": clean,
        "quarantined": quarantined,
        "errors": errors,
        "total": detected + clean,
    }

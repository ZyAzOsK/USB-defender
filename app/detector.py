# app/detector.py
"""
Unified threat detection engine.
Uses:
 - match_file() from signatures.py (now returns multi-tag results)
 - enrich_tag() from threat_intel.py
 - returns full structured detection results for ALL matches
"""

import os
from signatures import match_file
from threat_intel import enrich_tag


def detect_threat(file_path):
    """
    Returns a list of structured detection results, one per matched rule.
    Returns empty list if clean or file doesn't exist.
    """

    if not os.path.exists(file_path):
        return []

    detected, tags = match_file(file_path)

    if not detected:
        return []

    # Enrich every matched tag
    results = []
    for tag in tags:
        info = enrich_tag(tag)
        results.append(info)

    return results

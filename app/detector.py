# app/detector.py
"""
Unified threat detection engine.
Uses:
 - match_file() from signatures.py
 - enrich_tag() from threat_intel.py
 - returns full structured detection results
"""

import os
from signatures import match_file
from threat_intel import enrich_tag


def detect_threat(file_path):
    """
    Returns a list of structured detection results:
    [
        {
            "tag": "Suspicious_HTML_Executable",
            "severity": 8,
            "category": "Script Injection",
            "action": "Inspect and delete if untrusted",
            "description": "...",
        }
    ]
    """

    if not os.path.exists(file_path):
        return []

    detected, tag = match_file(file_path)

    if not detected:
        return []

    # threat_intel gives full structured info
    info = enrich_tag(tag)

    return [info]

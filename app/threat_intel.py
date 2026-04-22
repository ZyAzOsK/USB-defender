#!/usr/bin/env python3
"""
Threat Intelligence Enrichment Module
Maps detection tags to severity, category, and recommended response.
"""

THREAT_INTEL = {
    # --- Hash-based detections ---
    "Known_Malware_Hash": {
        "severity": 10,
        "category": "Malware",
        "action": "Quarantine immediately",
        "description": "File hash matches a known malware signature."
    },
    "EICAR_MD5": {
        "severity": 10,
        "category": "Malware (Test)",
        "action": "Quarantine immediately",
        "description": "File matches the EICAR antivirus test file (MD5 hash)."
    },
    "EICAR_SHA256": {
        "severity": 10,
        "category": "Malware (Test)",
        "action": "Quarantine immediately",
        "description": "File matches the EICAR antivirus test file (SHA256 hash)."
    },
    "Test_EICAR_Dummy_File": {
        "severity": 9,
        "category": "Malware (Test)",
        "action": "Quarantine immediately",
        "description": "File matches a known test/dummy malware sample hash."
    },

    # --- Heuristic detections ---
    "Suspicious_HTML_Executable": {
        "severity": 8,
        "category": "Script Injection",
        "action": "Inspect and delete if untrusted",
        "description": "HTML file contains embedded executable or PowerShell commands."
    },
    "Potential_Malicious_Python": {
        "severity": 7,
        "category": "Code Execution",
        "action": "Review script for unsafe subprocess or exec usage",
        "description": "Python file may contain unsafe execution patterns."
    },
    "Suspicious_Batch_Script": {
        "severity": 8,
        "category": "System Manipulation",
        "action": "Inspect batch file for destructive commands",
        "description": "Batch/CMD file contains potentially destructive system commands (del, format, reg, net user)."
    },
    "Suspicious_PowerShell_Script": {
        "severity": 9,
        "category": "Remote Code Execution",
        "action": "Quarantine and review for download/exec payloads",
        "description": "PowerShell script contains patterns associated with malicious download and execution (IEX, Invoke-WebRequest, encoded commands)."
    },
    "Suspicious_VBS_Script": {
        "severity": 8,
        "category": "Script Injection",
        "action": "Inspect for shell/object creation payloads",
        "description": "VBScript/JScript file uses WScript.Shell or CreateObject — common in dropper malware."
    },

    # --- Clean ---
    "Clean": {
        "severity": 0,
        "category": "Benign",
        "action": "No action needed",
        "description": "No suspicious patterns or hashes detected."
    }
}


def enrich_tag(tag):
    """Return full threat context for a given tag."""
    info = THREAT_INTEL.get(tag, None)
    if info:
        return {
            "tag": tag,
            "severity": info["severity"],
            "category": info["category"],
            "action": info["action"],
            "description": info["description"]
        }
    return {
        "tag": tag,
        "severity": 1,
        "category": "Unknown",
        "action": "Manual review recommended",
        "description": "No known intelligence available for this tag."
    }

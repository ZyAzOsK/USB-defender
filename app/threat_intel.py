#!/usr/bin/env python3
"""
Threat Intelligence Enrichment Module
Maps detection tags to severity, category, and recommended response.
"""

THREAT_INTEL = {
    "Known_Malware_Hash": {
        "severity": 10,
        "category": "Malware",
        "action": "Quarantine immediately",
        "description": "File hash matches a known malware signature (EICAR or test sample)."
    },
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

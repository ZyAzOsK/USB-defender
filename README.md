# USB-defender - under construction 🚧

# USB-Defender

*A portable USB security assistant for real-time malware detection, quarantine, and analysis.*

USB-Defender is a cross-platform security tool designed to run **from a USB drive or from the host machine**.
It monitors USB activity in real time, scans files using hash + heuristic signatures, and automatically **quarantines** dangerous files.

Built for **Linux (tested on Arch Linux)** and works on Windows where Python + watchdog are available.

---

# Features (Completed up to Phase 8)

### ✔ **1. Automatic USB Target Detection**

When launched, USB-Defender automatically detects the USB mount point to operate on.

### ✔ **2. One-Time Recursive Scanner**

Searches every file inside the USB:

* Clean
* Suspicious (patterns)
* Known malware (SHA256)

### ✔ **3. Real-Time Monitoring (Watchdog)**

Monitors the USB drive for:

* CREATED
* MODIFIED
* DELETED
* MOVED

Every event is scanned + enriched with threat intelligence.

### ✔ **4. Signature-Based Detection**

* SHA256 known malware hashes
* `signatures.json` is auto-generated and updateable

### ✔ **5. Heuristic Pattern Detection**

Detects malicious indicators:

* `<script>powershell`
* `cmd.exe`
* base64 payload strings
* risky Python code (`subprocess`, `exec`, etc.)

### ✔ **6. Threat Intelligence Layer**

Each finding is enriched with:

* Severity (0–10)
* Category (Malware / Script Injection / Code Exec / etc.)
* Recommended action
* Human-readable description

### ✔ **7. Logging System**

Logs go into:

* `app/usb_defender.db` (SQLite)
* `app/logs/activity.log` (text log)

### ✔ **8. Automatic Quarantine System**

High-severity threats (≥8) are:

* moved to `/USB/quarantine/UUID.qfile`
* metadata stored as `UUID.meta.json`
* inserted into the `quarantine` table

### ✔ **9. Quarantine Manager CLI**

Includes:

* List
* Restore
* Delete
* Summary dashboard

Examples:

```bash
python app/quarantine_manager.py --list
python app/quarantine_manager.py --restore 3
python app/quarantine_manager.py --delete 3
python app/quarantine_manager.py --summary
```

### ✔ **10. Quarantine Summary (Phase 8)**

`python app/quarantine_manager.py --summary` shows:

* Total quarantined
* Severity metrics
* Today's & this week's quarantines
* Top threat categories
* Auto-writes: `app/quarantine_summary.json`

---

# Architecture Overview

```
USB-Defender/
│
├── app/
│   ├── main.py                 # CLI menu: scan or monitor
│   ├── watcher.py              # Real-time filesystem monitor
│   ├── scanner.py              # One-time recursive scanner
│   ├── detector.py             # Hash + pattern detection engine
│   ├── signatures.py           # JSON-based signature system
│   ├── threat_intel.py         # Severity, category, description
│   ├── quarantine.py           # Auto-quarantine logic
│   ├── quarantine_manager.py   # List/restore/delete/summary
│   ├── reporter.py             # Log viewer + CSV exporter
│   ├── usb_defender.db         # SQLite database
│   └── logs/
│       └── activity.log        # Text log
│
└── signatures.json             # Auto-generated signature store
```

---

# Usage Guide

## **Start the program**

```bash
python app/main.py
```

### Option 1 — One-time Scan

Recursively scans all files on the USB.

### Option 2 — Real-Time Monitoring

Watches for new/modified files and instantly scans them:

* Prints detection results
* Quarantines high-severity threats automatically
* Logs everything to DB + text logs

---

# Reporter (Log Viewer)

### Last N entries:

```bash
python app/reporter.py --limit 20
```

### Filter by event type:

```bash
python app/reporter.py --event CREATED
```

### Export logs to CSV:

```bash
python app/reporter.py --export
```

---

# Quarantine Manager

### List all quarantined files:

```bash
python app/quarantine_manager.py --list
```

### Restore a quarantined file:

```bash
python app/quarantine_manager.py --restore <ID>
```

### Permanently delete:

```bash
python app/quarantine_manager.py --delete <ID>
```

### Show quarantine summary:

```bash
python app/quarantine_manager.py --summary
```

---

# Detection Pipeline

```
Filesystem Event
     ↓
detector.py
    → hash matching
    → heuristic scanning
     ↓
threat_intel.py (severity/category/action)
     ↓
watcher.py
     ↓
log_event() → SQLite + text log
     ↓
if severity >= 8 → quarantine.py
```

---

# Installation

Install dependencies:

```bash
pip install watchdog tabulate
```

---


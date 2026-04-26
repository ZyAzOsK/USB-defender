#!/usr/bin/env python3
"""
api.py
------
FastAPI server exposing REST + WebSocket endpoints for the
USB-Defender dashboard. Designed to run as a sidecar process
spawned by Tauri (or standalone for development).

Usage:
    python api.py                    # default: port 8642
    python api.py --port 9000        # custom port
    python api.py --host 0.0.0.0     # allow external connections
"""

import os
import sys
import json
import asyncio
import argparse
import platform
import threading
from pathlib import Path
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

# Ensure app modules are importable
sys.path.insert(0, os.path.dirname(__file__))

from db import init_db, get_connection, _db_lock, DB_FILE
from scanner import scan_target
from signatures import load_signatures, reload_signatures
from threat_intel import enrich_tag
from quarantine_manager import list_quarantined, restore_quarantined, delete_quarantined
from quarantine import update_summary, SUMMARY_FILE
from usb_detector import USBDetector

# ==============================
# App Lifecycle
# ==============================
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize DB on startup, start auto-scan detector."""
    init_db()
    yield
    # Shutdown: stop auto-scanner if running
    _autoscan_stop()

app = FastAPI(
    title="USB Defender API",
    description="REST + WebSocket API for USB-Defender dashboard",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — allow Tauri webview and dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==============================
# State
# ==============================
_monitor_task = None
_monitor_stop_event = threading.Event()
_ws_clients: list[WebSocket] = []
_scan_jobs: dict[str, dict] = {}

# Auto-scan state
_usb_detector: USBDetector | None = None
_autoscan_enabled = False
_autoscan_history: list[dict] = []  # recent auto-scan results


def _on_usb_inserted(mount_path: str):
    """Callback fired by USBDetector when a USB drive is inserted."""
    global _autoscan_history
    print(f"🔌 USB INSERTED: {mount_path} — auto-scanning...")

    try:
        result = scan_target(mount_path)
        entry = {
            "timestamp": datetime.now().isoformat(),
            "mount_path": mount_path,
            "summary": result,
            "status": "completed",
        }
    except Exception as e:
        entry = {
            "timestamp": datetime.now().isoformat(),
            "mount_path": mount_path,
            "summary": {"detected": 0, "clean": 0},
            "status": f"error: {e}",
        }

    _autoscan_history = [entry] + _autoscan_history[:19]  # keep last 20

    # Broadcast to all connected WebSocket clients
    _broadcast_autoscan_event(entry)
    print(f"✅ Auto-scan complete: {entry['summary']}")


def _broadcast_autoscan_event(entry: dict):
    """Send auto-scan result to all connected WebSocket clients."""
    import asyncio
    for ws in list(_ws_clients):
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.ensure_future(ws.send_json({
                    "type": "autoscan",
                    "data": entry,
                }))
        except Exception:
            pass


def _on_usb_removed(dev_path: str):
    """Callback fired when a USB drive is removed."""
    print(f"⏏️  USB REMOVED: {dev_path}")


def _autoscan_stop():
    """Stop the auto-scan detector if running."""
    global _usb_detector, _autoscan_enabled
    if _usb_detector and _usb_detector.running:
        _usb_detector.stop()
    _autoscan_enabled = False


# ==============================
# Health & Status
# ==============================
@app.get("/api/status")
async def get_status():
    """Health check + system info."""
    from main import find_usb_mount
    usb = find_usb_mount()
    return {
        "status": "running",
        "timestamp": datetime.now().isoformat(),
        "usb_detected": usb is not None,
        "usb_path": usb,
        "db_path": str(DB_FILE),
        "monitoring_active": _monitor_task is not None and _monitor_task.is_alive(),
        "autoscan_enabled": _autoscan_enabled,
        "autoscan_detector_running": _usb_detector is not None and _usb_detector.running,
        "platform": platform.system(),
    }

# ==============================
# Auto-Scan (USB Insertion Detection)
# ==============================
@app.post("/api/autoscan/enable")
async def enable_autoscan():
    """Enable automatic scanning on USB insertion."""
    global _usb_detector, _autoscan_enabled

    if _autoscan_enabled and _usb_detector and _usb_detector.running:
        return {"status": "already_enabled", "message": "Auto-scan is already active."}

    _usb_detector = USBDetector(on_insert=_on_usb_inserted, on_remove=_on_usb_removed)
    _usb_detector.start()
    _autoscan_enabled = True

    return {
        "status": "enabled",
        "platform": platform.system(),
        "message": f"Auto-scan enabled on {platform.system()}. USB insertions will trigger scans automatically.",
    }


@app.post("/api/autoscan/disable")
async def disable_autoscan():
    """Disable automatic scanning on USB insertion."""
    _autoscan_stop()
    return {"status": "disabled", "message": "Auto-scan disabled."}


@app.get("/api/autoscan/status")
async def autoscan_status():
    """Get current auto-scan status and recent history."""
    return {
        "enabled": _autoscan_enabled,
        "detector_running": _usb_detector is not None and _usb_detector.running,
        "platform": platform.system(),
        "history": _autoscan_history,
    }


# ==============================
# Portable USB Deployment
# ==============================
from pydantic import BaseModel
import shutil

class ArmUSBRequest(BaseModel):
    usb_path: str

@app.post("/api/arm-usb")
async def arm_usb(req: ArmUSBRequest):
    """Deploy the portable scanner binary to the specified USB drive root."""
    import platform

    # Normalize path — strip shell backslash-escapes and trailing slashes
    usb_path_str = req.usb_path.replace("\\ ", " ").rstrip("/").rstrip("\\")
    target_dir = Path(usb_path_str)
    if not target_dir.exists() or not target_dir.is_dir():
        raise HTTPException(status_code=400, detail=f"Invalid USB path: {target_dir}")

    # Determine which binary to copy based on host OS
    sys_name = platform.system().lower()
    binary_name = "usb-defender-linux"
    if sys_name == "windows":
        binary_name = "USBDefender.exe"
    elif sys_name == "darwin":
        binary_name = "usb-defender-macos"

    # When running as a PyInstaller frozen binary, __file__ is inside a temp
    # _MEIPASS directory. The portable binary is bundled next to sys.executable.
    if getattr(sys, 'frozen', False):
        # Inside Tauri bundle: portable binary sits alongside the sidecar exe
        exe_dir = Path(sys.executable).resolve().parent
        source_binary = exe_dir / binary_name
    else:
        # Development: look in portable/dist relative to project root
        project_root = Path(__file__).resolve().parent.parent
        source_binary = project_root / "portable" / "dist" / binary_name

    if not source_binary.exists():
        raise HTTPException(
            status_code=500,
            detail=(
                f"Portable binary not found at {source_binary}. "
                "The installer package may not include the portable scanner — "
                "download it separately from the Releases page."
            )
        )

    dest_binary = target_dir / binary_name
    try:
        shutil.copy2(source_binary, dest_binary)
        if sys_name != "windows":
            dest_binary.chmod(0o755)
        return {"status": "success", "message": f"Successfully deployed {binary_name} to {target_dir}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to copy binary: {str(e)}")


# ==============================
# Scan Endpoints
# ==============================
@app.post("/api/scan")
async def trigger_scan(path: str = Query(..., description="Path to scan")):
    """Trigger a one-time scan. Returns results directly."""
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail=f"Path not found: {path}")

    # Run scan in thread to not block
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, scan_target, path)

    # Fetch recent scan logs from DB
    with _db_lock:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT timestamp, file_path, tag, severity, category, action, description
            FROM logs WHERE event_type = 'Scan'
            ORDER BY id DESC LIMIT 200
        """)
        scan_logs = [
            {
                "timestamp": r[0], "file_path": r[1], "tag": r[2],
                "severity": r[3], "category": r[4], "action": r[5],
                "description": r[6]
            }
            for r in cur.fetchall()
        ]
        conn.close()

    return {
        "summary": result,
        "scan_path": path,
        "details": scan_logs,
    }


# ==============================
# Log Endpoints
# ==============================
@app.get("/api/logs")
async def get_logs(
    event: str = Query(None, description="Filter by event type"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Query event logs with optional filters."""
    with _db_lock:
        conn = get_connection()
        cur = conn.cursor()

        query = """
            SELECT id, timestamp, event_type, file_path, file_size, sha256,
                   tag, severity, category, action, description, quarantine_path
            FROM logs WHERE 1=1
        """
        params = []

        if event:
            query += " AND event_type = ?"
            params.append(event.upper())

        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cur.execute(query, params)
        rows = cur.fetchall()

        # Get total count
        count_query = "SELECT COUNT(*) FROM logs WHERE 1=1"
        count_params = []
        if event:
            count_query += " AND event_type = ?"
            count_params.append(event.upper())
        cur.execute(count_query, count_params)
        total = cur.fetchone()[0]

        conn.close()

    columns = ["id", "timestamp", "event_type", "file_path", "file_size",
               "sha256", "tag", "severity", "category", "action",
               "description", "quarantine_path"]

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "logs": [dict(zip(columns, row)) for row in rows],
    }


# ==============================
# Quarantine Endpoints
# ==============================
@app.get("/api/quarantine")
async def get_quarantine():
    """List all quarantined items."""
    rows = list_quarantined()
    columns = ["id", "timestamp", "original_path", "quarantine_path",
               "meta_path", "tag", "severity", "category"]

    return {
        "total": len(rows),
        "items": [dict(zip(columns, row)) for row in rows],
    }


@app.post("/api/quarantine/{entry_id}/restore")
async def restore_entry(entry_id: int):
    """Restore a quarantined file to its original location."""
    rows = list_quarantined()
    ids = [r[0] for r in rows]
    if entry_id not in ids:
        raise HTTPException(status_code=404, detail="Quarantine entry not found")

    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, restore_quarantined, entry_id)
    return {"status": "restored", "entry_id": entry_id}


@app.delete("/api/quarantine/{entry_id}")
async def delete_entry(entry_id: int):
    """Permanently delete a quarantined file."""
    rows = list_quarantined()
    ids = [r[0] for r in rows]
    if entry_id not in ids:
        raise HTTPException(status_code=404, detail="Quarantine entry not found")

    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, delete_quarantined, entry_id)
    return {"status": "deleted", "entry_id": entry_id}


@app.get("/api/quarantine/summary")
async def get_quarantine_summary():
    """Get quarantine summary statistics."""
    # Rebuild summary fresh
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, update_summary)

    if SUMMARY_FILE.exists():
        with open(SUMMARY_FILE) as f:
            return json.load(f)
    return {"stats": {"total_quarantined": 0}, "top_threats": []}


# ==============================
# Signatures Endpoints
# ==============================
@app.get("/api/signatures")
async def get_signatures():
    """Get current signature rules."""
    return load_signatures()


@app.put("/api/signatures")
async def update_signatures(payload: dict):
    """Update signature rules JSON."""
    from signatures import SIGNATURE_FILE
    with open(SIGNATURE_FILE, "w") as f:
        json.dump(payload, f, indent=4)
    reload_signatures()
    return {"status": "updated", "rules_count": len(payload.get("rules", []))}


# ==============================
# WebSocket: Real-time Monitor
# ==============================
@app.websocket("/ws/monitor")
async def ws_monitor(websocket: WebSocket):
    """
    WebSocket endpoint for real-time monitoring events.
    Client connects, sends a JSON with {"path": "/mount/usb"} to start.
    Server streams detection events as JSON frames.
    """
    await websocket.accept()
    _ws_clients.append(websocket)

    try:
        # Wait for client to send the target path
        data = await websocket.receive_json()
        target_path = data.get("path", "")

        if not target_path or not os.path.exists(target_path):
            await websocket.send_json({"error": f"Invalid path: {target_path}"})
            return

        await websocket.send_json({
            "type": "status",
            "message": f"Monitoring started on {target_path}"
        })

        # Start watchdog in a background thread
        from watcher import USBEventHandler
        from watchdog.observers import Observer

        log_path = os.path.join(os.path.dirname(__file__), "logs")
        handler = USBEventHandler(target_path, log_path)
        observer = Observer()
        observer.schedule(handler, target_path, recursive=True)
        observer.start()

        # Poll for new log entries and stream them
        last_id = _get_last_log_id()

        try:
            while True:
                await asyncio.sleep(0.5)

                new_entries = _get_logs_after(last_id)
                for entry in new_entries:
                    await websocket.send_json({
                        "type": "event",
                        "data": entry
                    })
                    last_id = max(last_id, entry["id"])

        except WebSocketDisconnect:
            pass
        finally:
            observer.stop()
            observer.join()

    except WebSocketDisconnect:
        pass
    finally:
        if websocket in _ws_clients:
            _ws_clients.remove(websocket)


def _get_last_log_id() -> int:
    """Get the ID of the most recent log entry."""
    with _db_lock:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT MAX(id) FROM logs")
        row = cur.fetchone()
        conn.close()
    return row[0] or 0


def _get_logs_after(after_id: int) -> list[dict]:
    """Get log entries with id > after_id."""
    with _db_lock:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT id, timestamp, event_type, file_path, tag, severity,
                   category, action, description
            FROM logs WHERE id > ?
            ORDER BY id ASC
        """, (after_id,))
        rows = cur.fetchall()
        conn.close()

    columns = ["id", "timestamp", "event_type", "file_path", "tag",
               "severity", "category", "action", "description"]
    return [dict(zip(columns, row)) for row in rows]


# ==============================
# Dashboard Stats (for overview)
# ==============================
@app.get("/api/stats")
async def get_dashboard_stats():
    """Aggregated statistics for the dashboard home page."""
    with _db_lock:
        conn = get_connection()
        cur = conn.cursor()

        # Total events
        cur.execute("SELECT COUNT(*) FROM logs")
        total_events = cur.fetchone()[0]

        # Events by type
        cur.execute("""
            SELECT event_type, COUNT(*) FROM logs
            GROUP BY event_type ORDER BY COUNT(*) DESC
        """)
        events_by_type = {r[0]: r[1] for r in cur.fetchall()}

        # Threats detected (severity > 0)
        cur.execute("SELECT COUNT(*) FROM logs WHERE severity > 0 AND tag != 'Clean'")
        threats_detected = cur.fetchone()[0]

        # Severity distribution
        cur.execute("""
            SELECT
                SUM(CASE WHEN severity >= 8 THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN severity >= 5 AND severity < 8 THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN severity > 0 AND severity < 5 THEN 1 ELSE 0 END) as low
            FROM logs WHERE tag != 'Clean'
        """)
        sev = cur.fetchone()
        severity_dist = {"critical": sev[0] or 0, "medium": sev[1] or 0, "low": sev[2] or 0}

        # Top threat categories
        cur.execute("""
            SELECT category, COUNT(*) FROM logs
            WHERE tag != 'Clean' AND severity > 0
            GROUP BY category ORDER BY COUNT(*) DESC LIMIT 5
        """)
        top_categories = [{"category": r[0], "count": r[1]} for r in cur.fetchall()]

        # Quarantine count
        cur.execute("SELECT COUNT(*) FROM quarantine")
        quarantined = cur.fetchone()[0]

        # Recent activity (last 10)
        cur.execute("""
            SELECT timestamp, event_type, file_path, tag, severity, category
            FROM logs ORDER BY id DESC LIMIT 10
        """)
        recent = [
            {"timestamp": r[0], "event_type": r[1], "file_path": r[2],
             "tag": r[3], "severity": r[4], "category": r[5]}
            for r in cur.fetchall()
        ]

        conn.close()

    return {
        "total_events": total_events,
        "threats_detected": threats_detected,
        "quarantined_files": quarantined,
        "severity_distribution": severity_dist,
        "events_by_type": events_by_type,
        "top_categories": top_categories,
        "recent_activity": recent,
    }


# ==============================
# CLI Entry Point
# ==============================
def main():
    parser = argparse.ArgumentParser(description="USB Defender API Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8642, help="Port to bind (default: 8642)")
    args = parser.parse_args()

    # Guard: if port is already in use (e.g. another instance is running),
    # exit cleanly instead of crashing with an ugly traceback.
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        if s.connect_ex((args.host, args.port)) == 0:
            print(f"⚠️  Port {args.port} is already in use — another instance may be running. Exiting.")
            sys.exit(0)

    print(f"🛡️  USB Defender API starting on http://{args.host}:{args.port}")
    print(f"📖 API docs at http://{args.host}:{args.port}/docs")

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()

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
import time
import asyncio
import argparse
import platform
import threading
import shutil
from pathlib import Path
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

# Ensure app modules are importable
sys.path.insert(0, os.path.dirname(__file__))

from db import init_db, get_connection, _db_lock, DB_FILE
from scanner import scan_target
from signatures import load_signatures, save_signatures
from quarantine_manager import list_quarantined, restore_quarantined, delete_quarantined
from quarantine import update_summary, SUMMARY_FILE
from usb_detector import USBDetector, list_removable_mounts
from paths import (
    normalize_target_path,
    check_scan_target,
    get_bundle_dir,
    get_executable_dir,
    get_data_dir,
)

APP_VERSION = "1.0.3"

# ==============================
# State
# ==============================
_ws_clients: list[WebSocket] = []

# The event loop uvicorn runs on. Captured at startup so worker threads can
# schedule coroutines onto it; asyncio.get_event_loop() from a non-async
# thread does not return the running loop, which is why auto-scan results
# never reached the dashboard.
_main_loop: asyncio.AbstractEventLoop | None = None

# Auto-scan state
_usb_detector: USBDetector | None = None
_autoscan_enabled = False
_autoscan_history: list[dict] = []          # recent auto-scan results
_autoscan_lock = threading.Lock()
_recent_autoscans: dict[str, float] = {}    # mount path -> last scan time
AUTOSCAN_DEDUPE_SECONDS = 15

# Live monitor state: one watchdog observer per path, reference counted so
# two dashboard clients watching the same drive don't double-scan every event.
_monitors: dict[str, dict] = {}
_monitor_lock = threading.Lock()

# Short-lived cache for mount enumeration. The dashboard polls /api/status
# every few seconds from multiple components; each call otherwise re-reads
# /proc/mounts and stats every sysfs entry.
_mounts_cache: tuple[float, list[str]] = (0.0, [])
MOUNTS_CACHE_TTL = 2.0


def _cached_mounts() -> list[str]:
    global _mounts_cache
    now = time.monotonic()
    stamp, value = _mounts_cache
    if now - stamp < MOUNTS_CACHE_TTL:
        return value
    value = list_removable_mounts()
    _mounts_cache = (now, value)
    return value


# ==============================
# App Lifecycle
# ==============================
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize DB on startup, tear down background workers on shutdown."""
    global _main_loop
    _main_loop = asyncio.get_running_loop()

    init_db()
    load_signatures()  # seeds the writable signatures.json on first run
    print(f"📁 Data directory: {get_data_dir()}", flush=True)

    yield

    _autoscan_stop()
    _stop_all_monitors()


app = FastAPI(
    title="USB Defender API",
    description="REST + WebSocket API for USB-Defender dashboard",
    version=APP_VERSION,
    lifespan=lifespan,
)

# CORS — the dashboard is a Tauri webview (origin tauri://localhost or
# http://localhost:1420 in dev). Listing origins explicitly means a random
# web page the user visits cannot drive this API, which matters because
# these endpoints delete and encrypt files.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "tauri://localhost",
        "http://tauri.localhost",
        "https://tauri.localhost",
        "http://localhost:1420",
        "http://127.0.0.1:1420",
    ],
    allow_origin_regex=r"^(tauri|https?)://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==============================
# Auto-scan plumbing
# ==============================
def _broadcast(message: dict):
    """
    Send a JSON frame to every connected WebSocket client from any thread.

    Uses run_coroutine_threadsafe against the captured loop; scheduling with
    asyncio.ensure_future from a worker thread silently did nothing.
    """
    if _main_loop is None or _main_loop.is_closed():
        return

    for ws in list(_ws_clients):
        async def _send(target=ws):
            try:
                await target.send_json(message)
            except Exception:
                # Client vanished — drop it so the list cannot grow forever.
                if target in _ws_clients:
                    _ws_clients.remove(target)

        try:
            asyncio.run_coroutine_threadsafe(_send(), _main_loop)
        except RuntimeError:
            pass


def _on_usb_inserted(mount_path: str):
    """Callback fired by USBDetector when a USB drive is inserted."""
    global _autoscan_history

    mount_path = normalize_target_path(mount_path)
    print(f"🔌 USB INSERTED: {mount_path} — auto-scanning...", flush=True)

    # udev 'add' plus a mount-poll tick can both report the same drive.
    now = time.monotonic()
    with _autoscan_lock:
        last = _recent_autoscans.get(mount_path, 0.0)
        if now - last < AUTOSCAN_DEDUPE_SECONDS:
            print(f"⏭  Skipping duplicate insert event for {mount_path}", flush=True)
            return
        _recent_autoscans[mount_path] = now

    problem = check_scan_target(mount_path)
    if problem:
        entry = {
            "timestamp": datetime.now().isoformat(),
            "mount_path": mount_path,
            "summary": {"detected": 0, "clean": 0, "quarantined": 0},
            "status": f"skipped: {problem}",
        }
    else:
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
                "summary": {"detected": 0, "clean": 0, "quarantined": 0},
                "status": f"error: {e}",
            }

    with _autoscan_lock:
        _autoscan_history = [entry] + _autoscan_history[:19]  # keep last 20

    _broadcast({"type": "autoscan", "data": entry})
    print(f"✅ Auto-scan complete: {entry['summary']}", flush=True)


def _on_usb_removed(dev_path: str):
    """Callback fired when a USB drive is removed."""
    print(f"⏏️  USB REMOVED: {dev_path}", flush=True)
    _broadcast({"type": "usb_removed", "data": {"path": dev_path}})


def _autoscan_stop():
    """Stop the auto-scan detector if running."""
    global _usb_detector, _autoscan_enabled
    if _usb_detector and _usb_detector.running:
        _usb_detector.stop()
    _usb_detector = None
    _autoscan_enabled = False


# ==============================
# Live monitor plumbing
# ==============================
def _start_monitor(path: str):
    """Start (or join) a watchdog observer for path. Returns the entry."""
    from watcher import USBEventHandler
    from watchdog.observers import Observer

    with _monitor_lock:
        entry = _monitors.get(path)
        if entry:
            entry["clients"] += 1
            return entry

        handler = USBEventHandler(path, str(get_data_dir() / "logs"))
        observer = Observer()
        observer.schedule(handler, path, recursive=True)
        observer.start()

        entry = {"observer": observer, "handler": handler, "clients": 1}
        _monitors[path] = entry
        print(f"👁  Monitoring started on {path}", flush=True)
        return entry


def _stop_monitor(path: str):
    """Release one client's hold on a monitor; stop it when the last leaves."""
    with _monitor_lock:
        entry = _monitors.get(path)
        if not entry:
            return
        entry["clients"] -= 1
        if entry["clients"] > 0:
            return
        _monitors.pop(path, None)

    try:
        entry["observer"].stop()
        entry["observer"].join(timeout=5)
    except Exception:
        pass
    print(f"🛑 Monitoring stopped on {path}", flush=True)


def _stop_all_monitors():
    with _monitor_lock:
        paths = list(_monitors.keys())
    for path in paths:
        with _monitor_lock:
            entry = _monitors.pop(path, None)
        if entry:
            try:
                entry["observer"].stop()
                entry["observer"].join(timeout=5)
            except Exception:
                pass


def _monitoring_active() -> bool:
    with _monitor_lock:
        return any(e["observer"].is_alive() for e in _monitors.values())


# ==============================
# Health & Status
# ==============================
@app.get("/api/status")
async def get_status():
    """Health check + system info."""
    mounts = _cached_mounts()
    usb = mounts[0] if mounts else None

    with _monitor_lock:
        monitored = list(_monitors.keys())

    return {
        "status": "running",
        "version": APP_VERSION,
        "timestamp": datetime.now().isoformat(),
        "usb_detected": usb is not None,
        "usb_path": usb,
        "usb_mounts": mounts,
        "db_path": str(DB_FILE),
        "data_dir": str(get_data_dir()),
        "monitoring_active": _monitoring_active(),
        "monitored_paths": monitored,
        "autoscan_enabled": _autoscan_enabled,
        "autoscan_detector_running": _usb_detector is not None and _usb_detector.running,
        "platform": platform.system(),
    }


@app.get("/api/mounts")
async def get_mounts():
    """List currently mounted removable volumes, for the UI drive picker."""
    mounts = _cached_mounts()
    return {"platform": platform.system(), "mounts": mounts}


# ==============================
# Auto-Scan (USB Insertion Detection)
# ==============================
@app.post("/api/autoscan/enable")
async def enable_autoscan():
    """Enable automatic scanning on USB insertion."""
    global _usb_detector, _autoscan_enabled

    if _autoscan_enabled and _usb_detector and _usb_detector.running:
        return {"status": "already_enabled", "message": "Auto-scan is already active."}

    detector = USBDetector(on_insert=_on_usb_inserted, on_remove=_on_usb_removed)
    try:
        detector.start()
    except OSError as e:
        raise HTTPException(status_code=501, detail=str(e))

    _usb_detector = detector
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
    with _autoscan_lock:
        history = list(_autoscan_history)

    return {
        "enabled": _autoscan_enabled,
        "detector_running": _usb_detector is not None and _usb_detector.running,
        "platform": platform.system(),
        "history": history,
    }


# ==============================
# Portable USB Deployment
# ==============================
class ArmUSBRequest(BaseModel):
    usb_path: str


def _portable_binary_candidates() -> list[Path]:
    """
    Every location the portable scanner might live, most likely first.

    Installed builds get it from Tauri's externalBin, which lands next to the
    main app executable under the canonical name. Dev builds read
    portable/dist. The legacy per-OS names are still accepted so a manually
    assembled tree keeps working.
    """
    sys_name = platform.system().lower()
    if sys_name == "windows":
        names = ["usb-defender-portable.exe", "USBDefender.exe"]
    elif sys_name == "darwin":
        names = ["usb-defender-portable", "usb-defender-macos"]
    else:
        names = ["usb-defender-portable", "usb-defender-linux"]

    exe_dir = get_executable_dir()
    project_root = Path(__file__).resolve().parent.parent

    dirs = [
        exe_dir,
        exe_dir / "bin",
        exe_dir.parent,
        exe_dir.parent / "lib" / "usb-defender",
        get_bundle_dir(),
        project_root / "portable" / "dist",
        project_root / "dashboard" / "src-tauri" / "sidecars",
    ]

    return [d / n for d in dirs for n in names]


def _deploy_name() -> str:
    """
    Filename to write on the USB drive. Kept as the platform-friendly names
    that scan.sh and scan.bat already look for.
    """
    sys_name = platform.system().lower()
    if sys_name == "windows":
        return "USBDefender.exe"
    if sys_name == "darwin":
        return "usb-defender-macos"
    return "usb-defender-linux"


def _launcher_candidates() -> list[Path]:
    """Locate the convenience launcher scripts to ship alongside the binary."""
    name = "scan.bat" if platform.system().lower() == "windows" else "scan.sh"
    project_root = Path(__file__).resolve().parent.parent
    return [
        get_bundle_dir() / name,
        get_executable_dir() / name,
        project_root / "portable" / name,
    ]


@app.post("/api/arm-usb")
async def arm_usb(req: ArmUSBRequest):
    """Deploy the portable scanner binary to the specified USB drive root."""
    usb_path = normalize_target_path(req.usb_path)
    target_dir = Path(usb_path)

    if not usb_path or not target_dir.is_dir():
        raise HTTPException(status_code=400, detail=f"Invalid USB path: {req.usb_path}")

    source_binary = next((c for c in _portable_binary_candidates() if c.is_file()), None)
    if source_binary is None:
        searched = "\n  ".join(str(c) for c in _portable_binary_candidates())
        raise HTTPException(
            status_code=500,
            detail=(
                "Portable scanner binary not found. Searched:\n  " + searched +
                "\nDownload it from the Releases page and place it next to the "
                "application executable, or run portable/build_portable.py."
            ),
        )

    dest_binary = target_dir / _deploy_name()
    try:
        shutil.copy2(source_binary, dest_binary)
        if platform.system().lower() != "windows":
            dest_binary.chmod(0o755)
    except OSError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to copy scanner to {dest_binary}: {e}",
        )

    # Best effort: a launcher script makes the drive double-clickable.
    deployed = [dest_binary.name]
    launcher = next((c for c in _launcher_candidates() if c.is_file()), None)
    if launcher is not None:
        try:
            dest_launcher = target_dir / launcher.name
            shutil.copy2(launcher, dest_launcher)
            if platform.system().lower() != "windows":
                dest_launcher.chmod(0o755)
            deployed.append(dest_launcher.name)
        except OSError:
            pass

    return {
        "status": "success",
        "deployed": deployed,
        "source": str(source_binary),
        "message": f"Deployed {' + '.join(deployed)} to {target_dir}",
    }


# ==============================
# Scan Endpoints
# ==============================
@app.post("/api/scan")
async def trigger_scan(path: str = Query(..., description="Path to scan")):
    """Trigger a one-time scan. Returns results directly."""
    target = normalize_target_path(path)

    problem = check_scan_target(target)
    if problem:
        # 400 rather than 404 — the path may well exist, we are refusing it.
        raise HTTPException(status_code=400, detail=problem)

    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, scan_target, target)

    # Fetch this scan's log rows
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
        "scan_path": target,
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
            # event_type is stored with mixed case ('Scan', 'Created'), so
            # compare case-insensitively instead of forcing upper().
            query += " AND UPPER(event_type) = ?"
            params.append(event.upper())

        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cur.execute(query, params)
        rows = cur.fetchall()

        count_query = "SELECT COUNT(*) FROM logs WHERE 1=1"
        count_params = []
        if event:
            count_query += " AND UPPER(event_type) = ?"
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
    if entry_id not in {r[0] for r in list_quarantined()}:
        raise HTTPException(status_code=404, detail="Quarantine entry not found")

    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, restore_quarantined, entry_id)

    # Confirm it actually left the table; restore_quarantined swallows errors.
    if entry_id in {r[0] for r in list_quarantined()}:
        raise HTTPException(
            status_code=500,
            detail="Restore failed — the quarantined payload or its metadata "
                   "could not be read. The entry was left untouched.",
        )
    return {"status": "restored", "entry_id": entry_id}


@app.delete("/api/quarantine/{entry_id}")
async def delete_entry(entry_id: int):
    """Permanently delete a quarantined file."""
    if entry_id not in {r[0] for r in list_quarantined()}:
        raise HTTPException(status_code=404, detail="Quarantine entry not found")

    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, delete_quarantined, entry_id)
    return {"status": "deleted", "entry_id": entry_id}


@app.get("/api/quarantine/summary")
async def get_quarantine_summary():
    """Get quarantine summary statistics."""
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, update_summary)

    if SUMMARY_FILE.exists():
        try:
            with open(SUMMARY_FILE) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            pass
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
    if not isinstance(payload.get("rules"), list):
        raise HTTPException(
            status_code=422,
            detail="Payload must contain a 'rules' array.",
        )
    if not isinstance(payload.get("malware_hashes", []), list):
        raise HTTPException(
            status_code=422,
            detail="'malware_hashes' must be an array when present.",
        )

    try:
        save_signatures(payload)
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"Could not save signatures: {e}")

    return {"status": "updated", "rules_count": len(payload.get("rules", []))}


# ==============================
# WebSocket: Real-time Monitor
# ==============================
async def _watch_for_disconnect(websocket: WebSocket, disconnected: asyncio.Event):
    """
    Consume incoming frames purely to notice when the client goes away.
    Without a pending receive, a disconnect is only discovered on the next
    send, which can leave the watchdog observer running for a long time.
    """
    try:
        while True:
            await websocket.receive_text()
    except Exception:
        disconnected.set()


@app.websocket("/ws/monitor")
async def ws_monitor(websocket: WebSocket):
    """
    WebSocket endpoint for real-time monitoring events.
    Client connects, sends {"path": "/mount/usb"} to start.
    Server streams detection events for that path as JSON frames.
    """
    await websocket.accept()
    _ws_clients.append(websocket)

    monitor_path = None
    disconnected = asyncio.Event()
    reader = None

    try:
        try:
            data = await websocket.receive_json()
        except Exception:
            return

        target_path = normalize_target_path(data.get("path", ""))
        problem = check_scan_target(target_path)
        if problem:
            await websocket.send_json({"type": "error", "error": problem})
            return

        try:
            _start_monitor(target_path)
            monitor_path = target_path
        except Exception as e:
            await websocket.send_json({
                "type": "error",
                "error": f"Could not start monitoring {target_path}: {e}",
            })
            return

        await websocket.send_json({
            "type": "status",
            "message": f"Monitoring started on {target_path}",
            "path": target_path,
        })

        reader = asyncio.create_task(_watch_for_disconnect(websocket, disconnected))
        last_id = _get_last_log_id()

        while not disconnected.is_set():
            try:
                await asyncio.wait_for(disconnected.wait(), timeout=0.5)
                break
            except asyncio.TimeoutError:
                pass

            for entry in _get_logs_after(last_id, target_path):
                await websocket.send_json({"type": "event", "data": entry})
                last_id = max(last_id, entry["id"])

    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"[ws_monitor] error: {e}", flush=True)
    finally:
        if reader is not None:
            reader.cancel()
        if monitor_path is not None:
            _stop_monitor(monitor_path)
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


def _get_logs_after(after_id: int, path_prefix: str | None = None) -> list[dict]:
    """
    Get log entries with id > after_id, optionally limited to a subtree.

    The prefix filter matters: a scan running elsewhere writes to the same
    logs table, and without it the Live Monitor showed events for files that
    have nothing to do with the drive being watched.
    """
    with _db_lock:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT id, timestamp, event_type, file_path, tag, severity,
                   category, action, description
            FROM logs WHERE id > ?
            ORDER BY id ASC LIMIT 500
        """, (after_id,))
        rows = cur.fetchall()
        conn.close()

    columns = ["id", "timestamp", "event_type", "file_path", "tag",
               "severity", "category", "action", "description"]
    entries = [dict(zip(columns, row)) for row in rows]

    if path_prefix:
        normalized = os.path.normcase(os.path.normpath(path_prefix))
        entries = [
            e for e in entries
            if e["file_path"] and os.path.normcase(
                os.path.normpath(e["file_path"])
            ).startswith(normalized)
        ]

    return entries


# ==============================
# Dashboard Stats (for overview)
# ==============================
@app.get("/api/stats")
async def get_dashboard_stats():
    """Aggregated statistics for the dashboard home page."""
    with _db_lock:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) FROM logs")
        total_events = cur.fetchone()[0]

        cur.execute("""
            SELECT event_type, COUNT(*) FROM logs
            GROUP BY event_type ORDER BY COUNT(*) DESC
        """)
        events_by_type = {r[0]: r[1] for r in cur.fetchall()}

        cur.execute("SELECT COUNT(*) FROM logs WHERE severity > 0 AND tag != 'Clean'")
        threats_detected = cur.fetchone()[0]

        cur.execute("""
            SELECT
                SUM(CASE WHEN severity >= 8 THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN severity >= 5 AND severity < 8 THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN severity > 0 AND severity < 5 THEN 1 ELSE 0 END) as low
            FROM logs WHERE tag != 'Clean'
        """)
        sev = cur.fetchone()
        severity_dist = {"critical": sev[0] or 0, "medium": sev[1] or 0, "low": sev[2] or 0}

        cur.execute("""
            SELECT category, COUNT(*) FROM logs
            WHERE tag != 'Clean' AND severity > 0
            GROUP BY category ORDER BY COUNT(*) DESC LIMIT 5
        """)
        top_categories = [{"category": r[0], "count": r[1]} for r in cur.fetchall()]

        cur.execute("SELECT COUNT(*) FROM quarantine")
        quarantined = cur.fetchone()[0]

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
def _port_in_use(host: str, port: int) -> bool:
    """
    True when something already accepts connections on host:port.

    A previous sidecar that outlived its parent window would otherwise make
    the new instance die on bind with an opaque traceback.
    """
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        return s.connect_ex((host, port)) == 0


def main():
    parser = argparse.ArgumentParser(description="USB Defender API Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8642, help="Port to bind (default: 8642)")
    parser.add_argument("--version", action="version", version=f"USB Defender API {APP_VERSION}")
    args = parser.parse_args()

    if _port_in_use(args.host, args.port):
        print(
            f"⚠️  Port {args.port} is already in use — another USB Defender "
            f"instance is already serving. Exiting.",
            flush=True,
        )
        sys.exit(0)

    print(f"🛡️  USB Defender API {APP_VERSION} starting on http://{args.host}:{args.port}", flush=True)
    print(f"📖 API docs at http://{args.host}:{args.port}/docs", flush=True)

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()

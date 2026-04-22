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

# ==============================
# App Lifecycle
# ==============================
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize DB on startup."""
    init_db()
    yield

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
    }


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

    print(f"🛡️  USB Defender API starting on http://{args.host}:{args.port}")
    print(f"📖 API docs at http://{args.host}:{args.port}/docs")

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()

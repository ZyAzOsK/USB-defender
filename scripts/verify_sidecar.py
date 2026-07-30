#!/usr/bin/env python3
"""
verify_sidecar.py
-----------------
Smoke-test a built usb-defender-api sidecar binary.

The point of this script is to catch, in CI, the class of failure that only
appears in a frozen build:

1. The binary starts and serves /api/status at all (missing hidden imports
   surface as an immediate crash).
2. /ws/monitor completes a WebSocket upgrade. When uvicorn has no WebSocket
   implementation bundled it answers the upgrade with 404 — which is exactly
   how the Live Monitor shipped broken in v1.0.2, silently, because nothing
   exercised it.
3. Writable state lands in a real user data directory rather than the
   PyInstaller _MEIPASS temp dir that is deleted on exit.

Usage:
    python scripts/verify_sidecar.py <path-to-sidecar-binary> [--port 8799]
"""

import argparse
import base64
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path


def wait_for_health(port: int, timeout: float = 25.0) -> dict:
    """Poll /api/status until it answers, returning the parsed payload."""
    deadline = time.time() + timeout
    last_error = None

    while time.time() < deadline:
        try:
            url = f"http://127.0.0.1:{port}/api/status"
            with urllib.request.urlopen(url, timeout=2) as resp:
                return json.load(resp)
        except Exception as e:  # connection refused while still booting
            last_error = e
            time.sleep(0.5)

    raise RuntimeError(f"sidecar never became healthy: {last_error}")


def check_websocket(port: int) -> str:
    """
    Perform a minimal RFC 6455 upgrade handshake.
    Returns the HTTP status line; '101' means WebSockets work.
    """
    key = base64.b64encode(os.urandom(16)).decode()
    request = (
        f"GET /ws/monitor HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"\r\n"
    )

    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        sock.sendall(request.encode())
        raw = sock.recv(256).decode(errors="ignore")
    finally:
        sock.close()

    return raw.splitlines()[0] if raw else "<no response>"


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke-test a built API sidecar")
    parser.add_argument("binary", help="Path to the usb-defender-api executable")
    parser.add_argument("--port", type=int, default=8799)
    args = parser.parse_args()

    binary = Path(args.binary).resolve()
    if not binary.is_file():
        print(f"FAIL: not a file: {binary}")
        return 1

    if os.name != "nt":
        binary.chmod(0o755)

    # Keep the probe's state out of the real user data directory.
    env = dict(os.environ)
    env["USB_DEFENDER_DATA_DIR"] = str(binary.parent / "_verify_data")

    print(f"launching {binary.name} on port {args.port}")
    proc = subprocess.Popen([str(binary), "--port", str(args.port)], env=env)

    failures = []
    try:
        status = wait_for_health(args.port)
        print(f"  /api/status ok — version={status.get('version')} "
              f"platform={status.get('platform')}")

        # The data dir must be a real, writable location outside _MEIPASS.
        data_dir = status.get("data_dir", "")
        print(f"  data_dir = {data_dir}")
        if not data_dir:
            failures.append("status did not report a data_dir")
        elif "_MEI" in data_dir:
            failures.append(
                f"data_dir points inside the PyInstaller temp dir ({data_dir}); "
                "the database would be deleted on exit"
            )

        status_line = check_websocket(args.port)
        print(f"  /ws/monitor handshake -> {status_line}")
        if "101" not in status_line:
            failures.append(
                f"WebSocket upgrade failed ({status_line}); the Live Monitor "
                "would be dead. Check the websockets hidden imports."
            )

    except Exception as e:
        failures.append(str(e))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    if failures:
        print("\nFAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1

    print("\nPASS: sidecar is healthy, WebSockets work, state is persistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""
test_api.py — Endpoint and threading behaviour of the FastAPI sidecar.

The most important test here is the auto-scan broadcast: results were
produced on a watchdog/detector worker thread and pushed with
asyncio.ensure_future(asyncio.get_event_loop(...)), which from a non-async
thread does not target the running loop. The scan happened, the dashboard
never heard about it, and nothing failed loudly.
"""

import os
import threading

import pytest
from fastapi.testclient import TestClient

import api as api_module


EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@pytest.fixture
def client():
    with TestClient(api_module.app) as c:
        yield c
    # Leave no observers or detector threads behind between tests.
    api_module._autoscan_stop()
    api_module._stop_all_monitors()
    api_module._ws_clients.clear()
    api_module._recent_autoscans.clear()
    api_module._autoscan_history.clear()


@pytest.fixture
def usb(tmp_path):
    """A fake removable drive with one real threat and one benign script."""
    drive = tmp_path / "drive"
    drive.mkdir()
    (drive / "virus.com").write_text(EICAR)
    (drive / "helper.py").write_text("import os\nprint(os.getcwd())\n")
    return drive


class TestStatus:
    def test_reports_expected_shape(self, client):
        body = client.get("/api/status").json()
        for key in ("status", "version", "usb_detected", "usb_mounts",
                    "data_dir", "monitoring_active", "platform"):
            assert key in body
        assert body["status"] == "running"
        assert isinstance(body["usb_mounts"], list)

    def test_data_dir_is_not_inside_pyinstaller_temp(self, client):
        assert "_MEI" not in client.get("/api/status").json()["data_dir"]

    def test_mounts_endpoint(self, client):
        body = client.get("/api/mounts").json()
        assert isinstance(body["mounts"], list)


class TestScanGuards:
    def test_refuses_filesystem_root(self, client):
        r = client.post("/api/scan", params={"path": os.sep})
        assert r.status_code == 400
        assert "protected" in r.json()["detail"].lower()

    def test_refuses_home(self, client):
        r = client.post("/api/scan", params={"path": os.path.expanduser("~")})
        assert r.status_code == 400

    def test_refuses_missing_path(self, client, tmp_path):
        r = client.post("/api/scan", params={"path": str(tmp_path / "absent")})
        assert r.status_code == 400

    def test_scan_quarantines_only_high_severity(self, client, usb):
        r = client.post("/api/scan", params={"path": str(usb)})
        assert r.status_code == 200
        summary = r.json()["summary"]

        # The EICAR file is gone and encrypted; the benign helper is untouched.
        assert not (usb / "virus.com").exists()
        assert (usb / "helper.py").exists()
        assert summary["quarantined"] == 1
        assert summary["detected"] == 1

        qfiles = list((usb / "quarantine").glob("*.qfile"))
        assert len(qfiles) == 1
        assert qfiles[0].read_bytes().startswith(b"gAAAAA")  # Fernet token

    def test_scan_normalizes_trailing_separator(self, client, usb):
        r = client.post("/api/scan", params={"path": str(usb) + os.sep})
        assert r.status_code == 200
        assert r.json()["scan_path"] == str(usb)


class TestQuarantineEndpoints:
    def test_restore_and_delete_roundtrip(self, client, usb):
        client.post("/api/scan", params={"path": str(usb)})

        items = client.get("/api/quarantine").json()["items"]
        assert len(items) == 1
        entry_id = items[0]["id"]

        assert client.post(f"/api/quarantine/{entry_id}/restore").status_code == 200
        assert (usb / "virus.com").exists()
        assert (usb / "virus.com").read_text() == EICAR
        assert client.get("/api/quarantine").json()["total"] == 0

    def test_delete_removes_payload(self, client, usb):
        client.post("/api/scan", params={"path": str(usb)})
        entry_id = client.get("/api/quarantine").json()["items"][0]["id"]

        assert client.delete(f"/api/quarantine/{entry_id}").status_code == 200
        assert client.get("/api/quarantine").json()["total"] == 0
        assert list((usb / "quarantine").glob("*.qfile")) == []

    def test_unknown_id_is_404(self, client):
        assert client.post("/api/quarantine/99999/restore").status_code == 404
        assert client.delete("/api/quarantine/99999").status_code == 404


class TestArmUsb:
    def test_rejects_invalid_path(self, client, tmp_path):
        r = client.post("/api/arm-usb", json={"usb_path": str(tmp_path / "nope")})
        assert r.status_code == 400

    def test_reports_search_locations_when_binary_absent(self, client, tmp_path, monkeypatch):
        monkeypatch.setattr(api_module, "_portable_binary_candidates", lambda: [])
        r = client.post("/api/arm-usb", json={"usb_path": str(tmp_path)})
        assert r.status_code == 500
        assert "not found" in r.json()["detail"].lower()

    def test_deploys_when_binary_present(self, client, tmp_path, monkeypatch):
        fake = tmp_path / "usb-defender-portable"
        fake.write_bytes(b"#!/bin/sh\nexit 0\n")
        monkeypatch.setattr(api_module, "_portable_binary_candidates", lambda: [fake])
        monkeypatch.setattr(api_module, "_launcher_candidates", lambda: [])

        drive = tmp_path / "drive"
        drive.mkdir()
        r = client.post("/api/arm-usb", json={"usb_path": str(drive)})
        assert r.status_code == 200
        assert r.json()["deployed"]
        assert any(drive.iterdir())


class TestSignatures:
    def test_get_returns_rules(self, client):
        assert isinstance(client.get("/api/signatures").json()["rules"], list)

    def test_put_rejects_malformed_payload(self, client):
        assert client.put("/api/signatures", json={"rules": "nope"}).status_code == 422
        assert client.put("/api/signatures", json={}).status_code == 422

    def test_put_persists_and_reloads(self, client):
        payload = {
            "malware_hashes": [],
            "rules": [{
                "name": "Custom_Rule",
                "extensions": [".xyz"],
                "strong_patterns": ["totally-unique-marker"],
                "patterns": [],
            }],
        }
        assert client.put("/api/signatures", json=payload).status_code == 200
        assert client.get("/api/signatures").json()["rules"][0]["name"] == "Custom_Rule"


class TestWebSocketMonitor:
    def test_rejects_unsafe_path(self, client):
        with client.websocket_connect("/ws/monitor") as ws:
            ws.send_json({"path": os.sep})
            msg = ws.receive_json()
            assert msg["type"] == "error"

    def test_accepts_valid_path_and_registers_monitor(self, client, tmp_path):
        drive = tmp_path / "watched"
        drive.mkdir()

        with client.websocket_connect("/ws/monitor") as ws:
            ws.send_json({"path": str(drive)})
            msg = ws.receive_json()
            assert msg["type"] == "status"
            assert msg["path"] == str(drive)
            assert api_module._monitoring_active() is True

        # Closing the socket must release the watchdog observer.
        assert api_module._monitoring_active() is False


class TestAutoscanBroadcast:
    """
    Regression test for the dead broadcast path.

    _on_usb_inserted runs on a detector thread. Scheduling the send with
    asyncio.get_event_loop()/ensure_future from there silently dropped the
    message; it must be handed to the captured loop instead.
    """

    def test_result_reaches_a_connected_websocket_client(self, client, usb, tmp_path):
        watched = tmp_path / "watched"
        watched.mkdir()

        with client.websocket_connect("/ws/monitor") as ws:
            assert ws.receive_json  # socket established
            ws.send_json({"path": str(watched)})
            assert ws.receive_json()["type"] == "status"

            # Fire the callback from a *worker thread*, as the real detector does.
            worker = threading.Thread(
                target=api_module._on_usb_inserted, args=(str(usb),)
            )
            worker.start()
            worker.join(timeout=30)
            assert not worker.is_alive()

            # Drain frames until the autoscan result arrives.
            autoscan = None
            for _ in range(40):
                msg = ws.receive_json()
                if msg.get("type") == "autoscan":
                    autoscan = msg
                    break
            assert autoscan is not None, "auto-scan result never reached the client"
            assert autoscan["data"]["status"] == "completed"
            assert autoscan["data"]["summary"]["quarantined"] == 1

    def test_history_records_the_scan(self, client, usb):
        api_module._on_usb_inserted(str(usb))
        history = client.get("/api/autoscan/status").json()["history"]
        assert len(history) == 1
        assert history[0]["mount_path"] == str(usb)

    def test_duplicate_insert_events_are_deduplicated(self, client, usb):
        """udev 'add' and the mount poller can both report the same drive."""
        api_module._on_usb_inserted(str(usb))
        api_module._on_usb_inserted(str(usb))
        assert len(client.get("/api/autoscan/status").json()["history"]) == 1

    def test_protected_mount_is_skipped_not_scanned(self, client):
        api_module._on_usb_inserted(os.path.expanduser("~"))
        history = client.get("/api/autoscan/status").json()["history"]
        assert history[0]["status"].startswith("skipped")


class TestLogs:
    def test_event_filter_is_case_insensitive(self, client, usb):
        client.post("/api/scan", params={"path": str(usb)})

        upper = client.get("/api/logs", params={"event": "SCAN"}).json()
        lower = client.get("/api/logs", params={"event": "scan"}).json()
        assert upper["total"] == lower["total"] > 0

    def test_pagination_bounds(self, client):
        assert client.get("/api/logs", params={"limit": 0}).status_code == 422
        assert client.get("/api/logs", params={"limit": 501}).status_code == 422


class TestStats:
    def test_shape(self, client):
        body = client.get("/api/stats").json()
        for key in ("total_events", "threats_detected", "quarantined_files",
                    "severity_distribution", "top_categories", "recent_activity"):
            assert key in body

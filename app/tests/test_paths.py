"""
test_paths.py — Tests for path resolution and scan-target safety.

These cover the two bug classes that made v1.0.2 misbehave off Linux:
a bare Windows drive spec being treated as the drive root, and writable
state resolving inside the PyInstaller temp dir.
"""

import os
import platform
import pytest

from paths import (
    normalize_target_path,
    path_basename,
    check_scan_target,
    get_data_dir,
    get_bundle_dir,
)


class TestNormalizeTargetPath:
    def test_bare_windows_drive_becomes_root(self):
        """
        'D:' is drive-*relative* to Windows APIs — os.walk('D:') walks the
        current directory on D:, not the drive. It must become 'D:\\'.
        """
        assert normalize_target_path("D:") in ("D:\\", "D:/")
        assert normalize_target_path("d:").lower().startswith("d:")

    def test_windows_drive_root_preserved(self):
        assert normalize_target_path("D:\\") == "D:\\"

    def test_shell_escaped_spaces_undone(self):
        assert normalize_target_path("/media/KALI\\ LINUX") == "/media/KALI LINUX"

    def test_trailing_separator_stripped(self):
        assert normalize_target_path("/media/usb/") == "/media/usb"
        assert normalize_target_path("/media/usb///") == "/media/usb"

    def test_filesystem_root_preserved(self):
        assert normalize_target_path("/") == "/"

    def test_surrounding_quotes_removed(self):
        assert normalize_target_path('"/media/my usb"') == "/media/my usb"

    def test_empty_input(self):
        assert normalize_target_path("") == ""
        assert normalize_target_path(None) == ""

    def test_tilde_expanded(self):
        assert not normalize_target_path("~/docs").startswith("~")


class TestPathBasename:
    @pytest.mark.parametrize("path,expected", [
        ("/media/usb/evil.exe", "evil.exe"),
        ("D:\\threats\\evil.exe", "evil.exe"),
        ("C:/mixed\\separators/file.txt", "file.txt"),
        ("/media/usb/", "usb"),
        ("plain.txt", "plain.txt"),
    ])
    def test_handles_both_separators(self, path, expected):
        """A Windows path viewed on Linux must still yield a filename."""
        assert path_basename(path) == expected

    def test_empty(self):
        assert path_basename("") == ""


class TestCheckScanTarget:
    def test_accepts_ordinary_directory(self, tmp_path):
        assert check_scan_target(str(tmp_path)) is None

    def test_rejects_filesystem_root(self):
        assert check_scan_target(os.sep) is not None

    def test_rejects_home_directory(self):
        """Scanning $HOME would quarantine documents in place."""
        assert check_scan_target(str(os.path.expanduser("~"))) is not None

    def test_rejects_missing_path(self, tmp_path):
        assert check_scan_target(str(tmp_path / "nope")) is not None

    def test_rejects_a_file(self, tmp_path):
        f = tmp_path / "a.txt"
        f.write_text("x")
        assert check_scan_target(str(f)) is not None

    def test_rejects_empty(self):
        assert check_scan_target("") is not None

    @pytest.mark.skipif(platform.system() == "Windows",
                        reason="POSIX-specific system directories")
    def test_rejects_system_directories(self):
        for candidate in ("/usr", "/etc", "/var"):
            if os.path.isdir(candidate):
                assert check_scan_target(candidate) is not None


class TestDataDir:
    def test_data_dir_is_writable_and_outside_bundle(self):
        """
        Writable state must never live in the PyInstaller extraction dir,
        which is deleted when the frozen process exits.
        """
        data_dir = get_data_dir()
        assert data_dir.is_dir()
        assert "_MEI" not in str(data_dir)

        probe = data_dir / ".write-probe"
        probe.write_text("ok")
        assert probe.read_text() == "ok"
        probe.unlink()

    def test_respects_env_override(self):
        """conftest sets USB_DEFENDER_DATA_DIR; the module must honour it."""
        assert str(get_data_dir()) == os.environ["USB_DEFENDER_DATA_DIR"]

    def test_bundle_dir_exists(self):
        assert get_bundle_dir().is_dir()

"""
test_encoding.py — Guards against locale-dependent text I/O.

Windows defaults to cp1252, Linux and macOS to UTF-8. Any text-mode open
without an explicit encoding therefore behaves differently per platform.
This bit us twice:

1. scripts/bump_version.py crashed in CI on Windows reading app/api.py,
   because the file contains UTF-8 emoji that cp1252 cannot decode.
2. The heuristic content scan decoded the *same* file differently on
   Windows and Linux, so a drive could get different verdicts depending on
   which machine scanned it.
"""

import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# Text-mode open()/read_text()/write_text() that should declare an encoding.
SOURCES = sorted(
    [p for p in (REPO_ROOT / "app").glob("*.py")]
    + [p for p in (REPO_ROOT / "scripts").glob("*.py")]
    + [REPO_ROOT / "portable" / "usb_defender_portable.py"]
)

OPEN_TEXT = re.compile(r"""open\(\s*[^)]*?["'][rwax]\+?["']""")
PATH_TEXT = re.compile(r"\.(read_text|write_text)\(")


class TestExplicitEncoding:
    @pytest.mark.parametrize("source", SOURCES, ids=lambda p: p.name)
    def test_text_io_declares_encoding(self, source):
        """Every text-mode file operation must pin its encoding."""
        offenders = []
        for lineno, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if '"rb"' in line or '"wb"' in line or "'rb'" in line or "'wb'" in line:
                continue
            if (OPEN_TEXT.search(line) or PATH_TEXT.search(line)) and "encoding=" not in line:
                offenders.append(f"{source.name}:{lineno}: {stripped}")

        assert not offenders, (
            "Text I/O without an explicit encoding decodes as cp1252 on "
            "Windows:\n  " + "\n  ".join(offenders)
        )


class TestVersionScriptIsPortable:
    def test_reads_every_version_source(self):
        """
        bump_version.py must parse all five declarations. It reads Python and
        JSON files containing emoji, which is what broke on Windows.
        """
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import bump_version

        versions = bump_version.read_versions()
        assert len(versions) == 5
        assert all(v is not None for v in versions.values()), versions
        assert len(set(versions.values())) == 1, f"version drift: {versions}"

    def test_check_mode_runs_clean(self):
        """Exercise the script end to end, as CI does."""
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "bump_version.py"), "--check"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr

    def test_survives_a_non_utf8_locale(self):
        """
        Force a legacy codepage and confirm the script still works. Without
        encoding= this reproduces the exact CI traceback.
        """
        import os
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "cp1252"
        env["PYTHONUTF8"] = "0"
        env["LC_ALL"] = "C"
        env["LANG"] = "C"

        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "bump_version.py"), "--check"],
            capture_output=True, text=True, env=env,
        )
        assert "UnicodeDecodeError" not in result.stderr, result.stderr
        assert result.returncode == 0, result.stdout + result.stderr


class TestConsoleOutputIsUnicodeSafe:
    """
    Writing console output must never terminate the process.

    Tauri spawns the API sidecar with a piped stdout. On Windows that means
    Python uses cp1252 rather than the Unicode console API, so the emoji in
    the startup banner raised UnicodeEncodeError and killed the sidecar
    before uvicorn bound its port — the dashboard just showed
    "Engine Offline". Forcing a legacy codec reproduces it on any platform.
    """

    LEGACY_ENV = {"PYTHONIOENCODING": "cp1252", "PYTHONUTF8": "0"}

    def _legacy_env(self, tmp_path):
        import os
        env = dict(os.environ)
        env.update(self.LEGACY_ENV)
        env["USB_DEFENDER_DATA_DIR"] = str(tmp_path / "data")
        return env

    def test_emoji_banner_survives_a_legacy_codepage(self, tmp_path):
        """Importing the app package must make stdout safe for its own output."""
        script = (
            "import sys; sys.path.insert(0, %r)\n"
            "import paths\n"
            "print('\\U0001F6E1\\uFE0F  USB Defender API starting')\n"
            "print('\\U0001F4D6 API docs')\n"
            "print('\\u26A0\\uFE0F  Port already in use')\n"
        ) % str(REPO_ROOT / "app")

        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, env=self._legacy_env(tmp_path),
        )
        assert "UnicodeEncodeError" not in result.stderr, result.stderr
        assert result.returncode == 0, result.stderr

    def test_unconfigured_stdout_would_have_failed(self, tmp_path):
        """
        Confirms the guard above is meaningful rather than vacuous: the same
        print without the reconfigure must still blow up.
        """
        result = subprocess.run(
            [sys.executable, "-c", "print('\\U0001F6E1\\uFE0F  banner')"],
            capture_output=True, text=True, env=self._legacy_env(tmp_path),
        )
        assert result.returncode != 0
        assert "UnicodeEncodeError" in result.stderr

    def test_portable_scanner_banner_survives_a_legacy_codepage(self, tmp_path):
        """
        The portable scanner prints a large box-drawing banner and runs on
        untrusted machines, where output is often redirected to a file.
        """
        target = tmp_path / "drive"
        target.mkdir()

        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "portable" / "usb_defender_portable.py"),
             "--path", str(target)],
            capture_output=True, text=True, env=self._legacy_env(tmp_path),
        )
        assert "UnicodeEncodeError" not in result.stderr, result.stderr
        assert result.returncode == 0, result.stderr

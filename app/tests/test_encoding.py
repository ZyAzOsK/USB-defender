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

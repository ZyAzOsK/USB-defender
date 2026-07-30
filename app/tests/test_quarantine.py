"""
test_quarantine.py — Tests for quarantine encryption/decryption pipeline.
"""

import os
import json
from quarantine import quarantine_file
from quarantine_manager import list_quarantined, restore_quarantined, delete_quarantined


class TestQuarantineEncryption:
    def _make_threat_file(self, tmp_path, content="MALICIOUS_PAYLOAD_DATA"):
        """Helper: create a fake threat file and return its path."""
        threat = tmp_path / "malware.exe"
        threat.write_text(content)
        return str(threat), content

    def test_quarantine_encrypts_file(self, fresh_db):
        """Quarantined file should be encrypted (not plaintext)."""
        qdir = fresh_db / "quarantine"
        qdir.mkdir()
        file_path, original = self._make_threat_file(fresh_db)

        info = {"tag": "TestMalware", "severity": 10, "category": "Malware",
                "action": "Quarantine", "description": "Test"}

        result = quarantine_file(file_path, info, str(qdir))
        # Returns the .qfile path on success so callers can log where it went.
        assert result is not None
        assert str(result).endswith(".qfile")

        # Original should be gone
        assert not os.path.exists(file_path)

        # .qfile should exist and NOT contain plaintext
        qfiles = list(qdir.glob("*.qfile"))
        assert len(qfiles) == 1
        encrypted = qfiles[0].read_bytes()
        assert original.encode() not in encrypted
        assert encrypted.startswith(b"gAAAAA")  # Fernet token prefix

    def test_quarantine_creates_metadata(self, fresh_db):
        """Quarantine should create .meta.json with encryption key."""
        qdir = fresh_db / "quarantine"
        qdir.mkdir()
        file_path, _ = self._make_threat_file(fresh_db)

        info = {"tag": "TestMalware", "severity": 10, "category": "Malware",
                "action": "Quarantine", "description": "Test"}

        quarantine_file(file_path, info, str(qdir))

        meta_files = list(qdir.glob("*.meta.json"))
        assert len(meta_files) == 1

        with open(meta_files[0]) as f:
            metadata = json.load(f)

        assert "encryption_key" in metadata
        assert len(metadata["encryption_key"]) > 0
        assert metadata["tag"] == "TestMalware"

    def test_quarantine_creates_db_record(self, fresh_db):
        """Quarantine should insert a record into the quarantine table."""
        qdir = fresh_db / "quarantine"
        qdir.mkdir()
        file_path, _ = self._make_threat_file(fresh_db)

        info = {"tag": "TestMalware", "severity": 10, "category": "Malware",
                "action": "Quarantine", "description": "Test"}

        quarantine_file(file_path, info, str(qdir))

        rows = list_quarantined()
        assert len(rows) == 1
        assert rows[0][5] == "TestMalware"  # tag column

    def test_restore_decrypts_correctly(self, fresh_db):
        """Restoring should produce exact original file content."""
        qdir = fresh_db / "quarantine"
        qdir.mkdir()
        file_path, original = self._make_threat_file(fresh_db)

        info = {"tag": "TestMalware", "severity": 10, "category": "Malware",
                "action": "Quarantine", "description": "Test"}

        quarantine_file(file_path, info, str(qdir))

        rows = list_quarantined()
        entry_id = rows[0][0]
        restore_quarantined(entry_id)

        # File should be back with correct content
        assert os.path.exists(file_path)
        restored = open(file_path).read()
        assert restored == original

    def test_restore_removes_db_record(self, fresh_db):
        """After restore, the quarantine DB record should be deleted."""
        qdir = fresh_db / "quarantine"
        qdir.mkdir()
        file_path, _ = self._make_threat_file(fresh_db)

        info = {"tag": "TestMalware", "severity": 10, "category": "Malware",
                "action": "Quarantine", "description": "Test"}

        quarantine_file(file_path, info, str(qdir))
        rows = list_quarantined()
        assert len(rows) == 1

        restore_quarantined(rows[0][0])
        rows_after = list_quarantined()
        assert len(rows_after) == 0

    def test_delete_removes_everything(self, fresh_db):
        """Delete should remove .qfile, .meta.json, and DB record."""
        qdir = fresh_db / "quarantine"
        qdir.mkdir()
        file_path, _ = self._make_threat_file(fresh_db)

        info = {"tag": "TestMalware", "severity": 10, "category": "Malware",
                "action": "Quarantine", "description": "Test"}

        quarantine_file(file_path, info, str(qdir))
        rows = list_quarantined()
        delete_quarantined(rows[0][0])

        # DB should be empty
        assert len(list_quarantined()) == 0
        # Files should be gone
        assert len(list(qdir.glob("*.qfile"))) == 0
        assert len(list(qdir.glob("*.meta.json"))) == 0


class TestQuarantineSizeCap:
    def test_oversized_file_is_not_reported_as_quarantined(self, fresh_db, monkeypatch):
        """
        quarantine_file returns the .qfile path or None. Returning a falsy
        non-None value (False) would make scanner.py's `is not None` check
        report an untouched file as quarantined.
        """
        import quarantine as q

        qdir = fresh_db / "quarantine"
        qdir.mkdir()
        big = fresh_db / "big.bin"
        big.write_bytes(b"\x00" * 2048)
        monkeypatch.setattr(q, "MAX_QUARANTINE_SIZE", 1024)

        result = q.quarantine_file(str(big), {"tag": "T", "severity": 10,
                                              "category": "c", "action": "a",
                                              "description": "d"}, str(qdir))
        assert result is None
        assert big.exists(), "oversized file must be left in place"
        assert list(qdir.glob("*.qfile")) == []

    def test_missing_file_returns_none(self, fresh_db):
        from quarantine import quarantine_file
        qdir = fresh_db / "quarantine"
        qdir.mkdir()
        result = quarantine_file(str(fresh_db / "absent.bin"),
                                 {"tag": "T", "severity": 10, "category": "c",
                                  "action": "a", "description": "d"}, str(qdir))
        assert result is None

"""
test_db.py — Tests for the unified database module.
"""

import sqlite3
from db import init_db, compute_sha256, get_connection, DB_FILE


class TestInitDB:
    def test_creates_all_tables(self, fresh_db):
        """Verify all 3 tables are created after init_db()."""
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cur.fetchall()}
        conn.close()

        assert "logs" in tables
        assert "quarantine" in tables
        assert "threats" in tables

    def test_idempotent(self, fresh_db):
        """init_db() should be safe to call multiple times."""
        init_db()
        init_db()
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cur.fetchall()}
        conn.close()
        assert len(tables) >= 3


class TestComputeSHA256:
    def test_known_string(self, tmp_path):
        """Hash of a known string should match expected value."""
        f = tmp_path / "test.txt"
        f.write_text("hello")
        sha = compute_sha256(str(f))
        # SHA256 of "hello" (no newline)
        assert sha == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    def test_nonexistent_file(self):
        """Should return None for a missing file."""
        result = compute_sha256("/nonexistent/path/file.xyz")
        assert result is None

    def test_empty_file(self, tmp_path):
        """Empty file should still return a valid SHA256."""
        f = tmp_path / "empty.txt"
        f.write_text("")
        sha = compute_sha256(str(f))
        assert sha is not None
        assert len(sha) == 64  # SHA256 hex length

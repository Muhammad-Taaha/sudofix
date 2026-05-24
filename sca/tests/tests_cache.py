import json
import tempfile
from pathlib import Path

from sca.cache import compute_delta, get_cached_file, get_db_path, initialize_db, store_file_result


def test_initialize_db_and_store():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        conn = initialize_db(db_path)
        # check tables exist
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        table_names = {t[0] for t in tables}
        assert {"file_cache", "manifest_cache", "api_cache"}.issubset(table_names)
        conn.close()

        store_file_result(
            db_path,
            "abc123",
            "/tmp/test.py",
            1234567890.0,
            {"license": "MIT"},
        )
        cached = get_cached_file(db_path, "abc123")
        assert cached == {"license": "MIT"}


def test_compute_delta():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "delta.db"
        # Pre-populate
        store_file_result(db_path, "h1", "a.py", 100.0, {})
        store_file_result(db_path, "h2", "b.py", 200.0, {})
        store_file_result(db_path, "h3", "c.py", 300.0, {})

        current = [
            ("a.py", "h1", 100.0),  # unchanged
            ("b.py", "h2_new", 200.0),  # changed hash
            ("d.py", "h4", 400.0),  # new
        ]
        delta = compute_delta(db_path, current)
        assert set(delta["unchanged"]) == {"a.py"}
        assert set(delta["changed"]) == {"b.py"}
        assert set(delta["new"]) == {"d.py"}

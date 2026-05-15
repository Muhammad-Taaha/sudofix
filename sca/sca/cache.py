"""
SQLite‑based caching for scan results, manifest graphs, and API responses.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from sca.config import DEFAULT_CACHE_DIR
from sca.utils import get_logger

logger = get_logger(__name__)


DB_FILENAME = "sca_cache.db"


def get_db_path(cache_dir: Optional[str] = None) -> Path:
    """Return the full path to the SQLite cache database."""
    base = Path(cache_dir or DEFAULT_CACHE_DIR)
    base.mkdir(parents=True, exist_ok=True)
    return base / DB_FILENAME


def initialize_db(db_path: Path) -> sqlite3.Connection:
    """Create tables if they don't exist and return a connection."""
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")

    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS file_cache (
            hash        TEXT PRIMARY KEY,
            path        TEXT NOT NULL,
            mtime       REAL,
            scan_timestamp TEXT NOT NULL,
            result_json TEXT
        );

        CREATE TABLE IF NOT EXISTS manifest_cache (
            hash        TEXT PRIMARY KEY,
            graph_blob  BLOB,
            scan_timestamp TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS api_cache (
            url         TEXT PRIMARY KEY,
            response    BLOB,
            timestamp   TEXT NOT NULL
        );
        """
    )
    conn.commit()
    return conn


# ------------------------------------------------------------------ public API
def get_cached_file(db_path: Path, file_hash: str) -> Optional[Dict[str, Any]]:
    """Retrieve cached scan result for a file hash."""
    conn = initialize_db(db_path)
    try:
        row = conn.execute(
            "SELECT result_json FROM file_cache WHERE hash = ?", (file_hash,)
        ).fetchone()
        if row and row[0]:
            return json.loads(row[0])
        return None
    finally:
        conn.close()


def store_file_result(
    db_path: Path,
    file_hash: str,
    path: str,
    mtime: float,
    result: Dict[str, Any],
) -> None:
    """Insert or replace a file scan result."""
    conn = initialize_db(db_path)
    try:
        conn.execute(
            """
            INSERT OR REPLACE INTO file_cache (hash, path, mtime, scan_timestamp, result_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (file_hash, path, mtime, _now_iso(), json.dumps(result)),
        )
        conn.commit()
    finally:
        conn.close()


def get_manifest_cache(db_path: Path, manifest_hash: str) -> Optional[bytes]:
    conn = initialize_db(db_path)
    try:
        row = conn.execute(
            "SELECT graph_blob FROM manifest_cache WHERE hash = ?", (manifest_hash,)
        ).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def store_manifest_cache(db_path: Path, manifest_hash: str, graph_blob: bytes) -> None:
    conn = initialize_db(db_path)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO manifest_cache (hash, graph_blob, scan_timestamp) VALUES (?, ?, ?)",
            (manifest_hash, graph_blob, _now_iso()),
        )
        conn.commit()
    finally:
        conn.close()


def get_api_cache(db_path: Path, url: str) -> Optional[bytes]:
    conn = initialize_db(db_path)
    try:
        row = conn.execute("SELECT response FROM api_cache WHERE url = ?", (url,)).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def store_api_cache(db_path: Path, url: str, response: bytes) -> None:
    conn = initialize_db(db_path)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO api_cache (url, response, timestamp) VALUES (?, ?, ?)",
            (url, response, _now_iso()),
        )
        conn.commit()
    finally:
        conn.close()


def compute_delta(
    db_path: Path,
    current_files: List[Tuple[str, str, float]],  # (path, hash, mtime)
) -> Dict[str, List[str]]:
    """
    Compare current files with cached entries and return:
        new: list of paths never seen before
        changed: paths with existing hash but different hash or mtime
        unchanged: paths with identical hash and mtime
    """
    conn = initialize_db(db_path)
    try:
        # Fetch all cached entries
        cached = {
            row[1]: (row[0], row[2])  # path -> (hash, mtime)
            for row in conn.execute("SELECT hash, path, mtime FROM file_cache")
        }

        new, changed, unchanged = [], [], []
        current_paths_set = set()
        for path, file_hash, mtime in current_files:
            current_paths_set.add(path)
            if path not in cached:
                new.append(path)
            else:
                cached_hash, cached_mtime = cached[path]
                if cached_hash == file_hash and cached_mtime == mtime:
                    unchanged.append(path)
                else:
                    changed.append(path)

        # Files that were in cache but no longer present → can be ignored or logged
        removed = [p for p in cached if p not in current_paths_set]
        if removed:
            logger.debug("Files removed since last scan", count=len(removed))

        return {"new": new, "changed": changed, "unchanged": unchanged}
    finally:
        conn.close()


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())

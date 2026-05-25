"""Stream scan results to an SQLite output database to limit memory usage."""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Dict, Any, Optional

from sca.utils import get_logger

logger = get_logger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sub_project TEXT NOT NULL,
    category TEXT NOT NULL,
    data_json TEXT NOT NULL,
    timestamp TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
"""

class StreamingWriter:
    """Write findings incrementally to an SQLite database."""

    def __init__(self, output_path: Path):
        self.conn = sqlite3.connect(str(output_path))
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def write_finding(self, sub_project: str, category: str, data: Any):
        """Insert a single finding."""
        self.conn.execute(
            "INSERT INTO findings(sub_project, category, data_json, timestamp) VALUES(?,?,?,?)",
            (sub_project, category, json.dumps(data, default=str), time.strftime("%Y-%m-%dT%H:%M:%S")),
        )

    def write_many(self, sub_project: str, category: str, items: list):
        """Insert a batch of findings."""
        for item in items:
            self.write_finding(sub_project, category, item)
        self.conn.commit()

    def close(self):
        self.conn.commit()
        self.conn.close()
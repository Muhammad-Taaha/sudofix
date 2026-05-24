#!/usr/bin/env python3
"""
Offline vulnerability database updater.

Downloads OSV data dump (https://osv.dev/data) and imports into SQLite.
Usage:
    python -m sca.db.update_db --download   # fetch latest dump and import
    python -m sca.db.update_db --input <dir> # import from local directory of JSON files
"""

import argparse
import json
import os
import sqlite3
import sys
import tempfile
import zipfile
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

import requests
from cvss import CVSS3

from sca.utils import get_logger

logger = get_logger(__name__)

DB_PATH_DEFAULT = Path(__file__).resolve().parent / "vulnerabilities.db"
# OSV.dev no longer provides export.zip - use GitHub releases instead
OSV_DATA_URL = "https://github.com/google/osv.dev/releases/download/2024-07-01/all.json"

SCHEMA = """
CREATE TABLE IF NOT EXISTS packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    purl TEXT UNIQUE
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    summary TEXT,
    details TEXT,
    severity TEXT,
    cvss_score REAL,
    cvss_vector TEXT,
    published TEXT,
    modified TEXT
);

CREATE TABLE IF NOT EXISTS package_vulnerabilities (
    package_id INTEGER,
    vulnerability_id TEXT,
    fixed_version TEXT,
    introduced_version TEXT,
    FOREIGN KEY(package_id) REFERENCES packages(id),
    FOREIGN KEY(vulnerability_id) REFERENCES vulnerabilities(id),
    PRIMARY KEY(package_id, vulnerability_id)
);

CREATE TABLE IF NOT EXISTS file_hashes (
    hash TEXT PRIMARY KEY,
    vulnerability_id TEXT NOT NULL,
    filename TEXT,
    FOREIGN KEY(vulnerability_id) REFERENCES vulnerabilities(id)
);

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE INDEX IF NOT EXISTS idx_packages_name_eco ON packages(name, ecosystem);
CREATE INDEX IF NOT EXISTS idx_pkg_vuln_vuln ON package_vulnerabilities(vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
"""

def init_db(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.executescript(SCHEMA)
    conn.commit()
    return conn

def download_dump(dest_dir: Path) -> Path:
    logger.info("Downloading OSV data dump...")
    response = requests.get(OSV_DATA_URL, stream=True)
    response.raise_for_status()
    zip_path = dest_dir / "osv_data.zip"
    with open(zip_path, "wb") as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)
    logger.info("Download complete")
    return zip_path

def extract_dump(zip_path: Path, extract_to: Path) -> Path:
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(extract_to)
    return extract_to / "osv_data"

def import_osv_json(json_file: Path, conn: sqlite3.Connection):
    """Parse a single OSV JSON and insert into DB."""
    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    vuln_id = data.get("id", "")
    if not vuln_id:
        return

    summary = data.get("summary", "")
    details = data.get("details", "")
    severity = None
    cvss_score = None
    cvss_vector = None

    for db_entry in data.get("database_specific", {}).get("severity", []):
        if db_entry.get("type") == "CVSS_V3":
            cvss_vector = db_entry.get("score", "")
        elif db_entry.get("type") == "CVSS_V2":
            cvss_vector = db_entry.get("score", "")
        if db_entry.get("severity"):
            severity = db_entry["severity"]

    if cvss_vector:
        try:
            c = CVSS3(cvss_vector)
            cvss_score = c.scores()[0]
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            elif cvss_score >= 0.1:
                severity = "LOW"
            else:
                severity = "NONE"
        except Exception:
            pass
    if not severity:
        severity = data.get("severity", "UNKNOWN").upper()

    published = data.get("published", "")
    modified = data.get("modified", "")

    conn.execute(
        "INSERT OR REPLACE INTO vulnerabilities(id, summary, details, severity, cvss_score, cvss_vector, published, modified) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (vuln_id, summary, details, severity, cvss_score, cvss_vector, published, modified),
    )

    for affected in data.get("affected", []):
        pkg_info = affected.get("package", {})
        pkg_name = pkg_info.get("name", "")
        ecosystem = pkg_info.get("ecosystem", "")
        purl = pkg_info.get("purl", "")

        if not pkg_name:
            continue

        conn.execute(
            "INSERT OR IGNORE INTO packages(name, ecosystem, purl) VALUES(?,?,?)",
            (pkg_name, ecosystem, purl),
        )
        package_id = conn.execute(
            "SELECT id FROM packages WHERE name=? AND ecosystem=?", (pkg_name, ecosystem)
        ).fetchone()[0]

        introduced = None
        fixed = None
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if event.get("introduced"):
                    introduced = event["introduced"]
                if event.get("fixed"):
                    fixed = event["fixed"]
            conn.execute(
                "INSERT OR IGNORE INTO package_vulnerabilities(package_id, vulnerability_id, fixed_version, introduced_version) "
                "VALUES(?,?,?,?)",
                (package_id, vuln_id, fixed, introduced),
            )
        if not affected.get("ranges"):
            conn.execute(
                "INSERT OR IGNORE INTO package_vulnerabilities(package_id, vulnerability_id) VALUES(?,?)",
                (package_id, vuln_id),
            )

def update_db(db_path: Path, input_dir: Path, download: bool = False):
    conn = init_db(db_path)
    if download:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            zip_path = download_dump(tmp)
            extract_dir = extract_dump(zip_path, tmp)
            input_dir = extract_dir

    json_files = list(input_dir.rglob("*.json"))
    logger.info(f"Importing {len(json_files)} OSV files...")
    for i, f in enumerate(json_files):
        if i % 1000 == 0:
            logger.info(f"Processed {i}/{len(json_files)}")
        try:
            import_osv_json(f, conn)
        except Exception as e:
            logger.warning(f"Failed to import {f}: {e}")

    conn.execute(
        "INSERT OR REPLACE INTO metadata(key, value) VALUES('last_updated', ?)",
        (datetime.now(timezone.utc).isoformat(),),
    )
    conn.commit()
    conn.close()
    logger.info("Database update complete.")

def main():
    parser = argparse.ArgumentParser(description="Update vulnerability database")
    parser.add_argument("--db", default=str(DB_PATH_DEFAULT), help="Path to SQLite DB")
    parser.add_argument("--input", help="Directory containing OSV JSON files")
    parser.add_argument("--download", action="store_true", help="Download latest OSV dump")
    args = parser.parse_args()

    if not args.input and not args.download:
        parser.error("Either --input or --download required")
    input_dir = Path(args.input) if args.input else None
    update_db(Path(args.db), input_dir, download=args.download)

if __name__ == "__main__":
    main()

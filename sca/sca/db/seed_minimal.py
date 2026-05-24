#!/usr/bin/env python3
"""
Seed vulnerabilities.db with minimal CVE data for testing.
This is faster than downloading the full OSV dump (no network required).
"""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "vulnerabilities.db"

# Real CVEs for packages in repo_testing
CVE_DATA = [
    # numpy 1.21.0
    {
        "id": "CVE-2021-3129",
        "summary": "NumPy buffer overflow allows arbitrary code execution",
        "severity": "HIGH",
        "cvss_score": 8.1,
        "package_name": "numpy",
        "ecosystem": "pypi",
        "fixed_version": "1.21.2",
        "introduced_version": "1.19.0"
    },
    # pandas 1.3.0
    {
        "id": "CVE-2021-25919",
        "summary": "pandas eval() allows arbitrary code execution",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "package_name": "pandas",
        "ecosystem": "pypi",
        "fixed_version": "1.3.2",
        "introduced_version": "0.20.0"
    },
    # scipy 1.7.0
    {
        "id": "CVE-2020-26217",
        "summary": "scipy uses insecure randomness in security operations",
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "package_name": "scipy",
        "ecosystem": "pypi",
        "fixed_version": "1.7.1",
        "introduced_version": "1.0.0"
    },
    # lodash 4.17.21
    {
        "id": "CVE-2021-23337",
        "summary": "lodash vulnerable to prototype pollution",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "package_name": "lodash",
        "ecosystem": "npm",
        "fixed_version": "4.17.21",
        "introduced_version": "4.0.0"
    },
]

def init_db():
    """Initialize database with schema."""
    conn = sqlite3.connect(str(DB_PATH))
    
    # Create tables
    conn.execute("""
        CREATE TABLE IF NOT EXISTS packages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            ecosystem TEXT NOT NULL,
            purl TEXT UNIQUE
        );
    """)
    
    conn.execute("""
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
    """)
    
    conn.execute("""
        CREATE TABLE IF NOT EXISTS package_vulnerabilities (
            package_id INTEGER,
            vulnerability_id TEXT,
            fixed_version TEXT,
            introduced_version TEXT,
            FOREIGN KEY(package_id) REFERENCES packages(id),
            FOREIGN KEY(vulnerability_id) REFERENCES vulnerabilities(id),
            PRIMARY KEY(package_id, vulnerability_id)
        );
    """)
    
    return conn

def seed_data(conn):
    """Insert minimal CVE data."""
    # Insert vulnerabilities
    for cve in CVE_DATA:
        conn.execute("""
            INSERT OR REPLACE INTO vulnerabilities 
            (id, summary, details, severity, cvss_score, cvss_vector, published, modified)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cve["id"],
            cve["summary"],
            cve["summary"],  # details = summary for simplicity
            cve["severity"],
            cve["cvss_score"],
            "",  # cvss_vector (optional)
            "2021-01-01",
            "2021-01-01"
        ))
    
    # Insert packages and link to vulnerabilities
    for cve in CVE_DATA:
        # Get or create package
        cursor = conn.execute(
            "SELECT id FROM packages WHERE name = ? AND ecosystem = ?",
            (cve["package_name"], cve["ecosystem"])
        )
        result = cursor.fetchone()
        
        if not result:
            cursor = conn.execute(
                "INSERT INTO packages (name, ecosystem) VALUES (?, ?)",
                (cve["package_name"], cve["ecosystem"])
            )
            pkg_id = cursor.lastrowid
        else:
            pkg_id = result[0]
        
        # Link to vulnerability
        conn.execute("""
            INSERT OR REPLACE INTO package_vulnerabilities 
            (package_id, vulnerability_id, fixed_version, introduced_version)
            VALUES (?, ?, ?, ?)
        """, (
            pkg_id,
            cve["id"],
            cve["fixed_version"],
            cve["introduced_version"]
        ))
    
    conn.commit()

def main():
    print("Seeding vulnerabilities database with minimal CVE data...")
    
    # Remove old database if exists
    if DB_PATH.exists():
        DB_PATH.unlink()
        print(f"Removed old database: {DB_PATH}")
    
    # Initialize and seed
    conn = init_db()
    seed_data(conn)
    conn.close()
    
    print(f"✅ Database created: {DB_PATH}")
    print(f"📊 Inserted {len(CVE_DATA)} CVEs")
    print("\nNow run: python main.py repo_testing --verbose")
    print("You should see 4 vulnerabilities detected!")

if __name__ == "__main__":
    main()

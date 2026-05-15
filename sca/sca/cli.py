"""
Command‑line interface for the SCA toolkit.

Usage:
    sca scan <project_path> [--cache-dir ...] [--history] [--json]
    sca update-db [--download]
    sca rules list
    sca config init
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from sca import analyze
from sca.utils import get_logger

logger = get_logger(__name__)


def main():
    parser = argparse.ArgumentParser(prog="sca", description="Software Composition Analysis Toolkit")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- scan ---
    scan_parser = subparsers.add_parser("scan", help="Run a full SCA scan")
    scan_parser.add_argument("project_path", help="Path to the project directory")
    scan_parser.add_argument("--cache-dir", help="Custom cache directory")
    scan_parser.add_argument("--history", action="store_true", help="Include git history scanning")
    scan_parser.add_argument("--max-history-commits", type=int, help="Limit history commits")
    scan_parser.add_argument("--history-since", help="Only scan commits after this date")
    scan_parser.add_argument("--json", action="store_true", help="Output raw JSON")

    # --- update-db ---
    update_parser = subparsers.add_parser("update-db", help="Update the vulnerability database")
    update_parser.add_argument("--download", action="store_true", help="Download latest OSV dump")
    update_parser.add_argument("--input", help="Directory containing OSV JSON files")

    # --- rules list ---
    subparsers.add_parser("rules", help="List available rules")  # will be handled below

    # --- config init ---
    subparsers.add_parser("config", help="Initialize a default config file")

    args = parser.parse_args()

    if args.command == "scan":
        result = analyze(
            project_path=args.project_path,
            cache_dir=args.cache_dir,
            include_git_history=args.history,
            max_history_commits=args.max_history_commits,
            history_since=args.history_since,
        )
        if args.json:
            print(json.dumps(result, indent=2, default=str))
        else:
            _print_summary(result)

    elif args.command == "update-db":
        from sca.db.update_db import update_db, DB_PATH_DEFAULT
        if not args.download and not args.input:
            update_parser.error("Either --download or --input required")
        input_dir = Path(args.input) if args.input else None
        update_db(DB_PATH_DEFAULT, input_dir, download=args.download)

    elif args.command == "rules":
        _list_rules()

    elif args.command == "config":
        _init_config()


def _print_summary(result: dict):
    """Pretty‑print a scan summary to the console."""
    sub_projects = result.get("sub_projects", [])
    if not sub_projects:
        print("No sub‑projects found.")
        return

    for sp in sub_projects:
        print(f"\n=== {sp.get('project_path', 'unknown')} ===")
        print(f"  Packages: {len(sp.get('packages', []))}")
        print(f"  License findings: {len(sp.get('license_findings', []))}")
        print(f"  Vendored matches: {len(sp.get('vendored_matches', []))}")
        print(f"  Rule violations: {len(sp.get('rule_findings', []))}")
        print(f"  Vulnerabilities: {len(sp.get('vulnerabilities', []))}")
        print(f"  Outdated dependencies: {len(sp.get('outdated', []))}")


def _list_rules():
    """Print all rule IDs found in the default rules directory."""
    from sca.rule_scanner import RuleScanner
    try:
        scanner = RuleScanner()
        rules_dir = scanner.rules_dir
    except ImportError:
        print("ast‑grep not installed; cannot list rules.")
        return
    if not rules_dir.is_dir():
        print(f"No rules directory found at {rules_dir}")
        return
    rules = list(rules_dir.glob("*.yml"))
    if not rules:
        print("No rule files found.")
    else:
        print("Available rules:")
        for r in rules:
            print(f"  {r.stem}")


def _init_config():
    """Create a default sca‑config.yml in the current directory."""
    config_path = Path.cwd() / "sca-config.yml"
    if config_path.exists():
        print(f"{config_path} already exists.")
        return
    config_content = """# SCA Toolkit configuration
cache_dir: ~/.cache/sca
ignore_patterns:
  - .git
  - node_modules
  - __pycache__
  - vendor
  - dist
  - build
timeouts:
  file_scan: 120
  network: 30
severity_threshold: LOW
"""
    config_path.write_text(config_content)
    print(f"Created default config: {config_path}")


if __name__ == "__main__":
    main()
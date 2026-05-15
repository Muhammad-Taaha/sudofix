"""
Software Composition Analysis Toolkit – Main entry point.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Dict, List, Optional

from sca.utils import get_logger
from sca.ecosystem import detect_manifests
from sca.resolver.registry import ResolverRegistry
from sca.resolver.npm import NpmResolver
from sca.resolver.pypi import PypiResolver
from sca.resolver.maven import MavenResolver
from sca.resolver.go import GoResolver
from sca.file_hasher import discover_files
from sca.import_mapper import map_imports
from sca.scanners import LicenseScanner, VendoredScanner
from sca.rule_scanner import RuleScanner, HAS_AST_GREP
from sca.vulnerability_mapper import VulnerabilityMapper
from sca.outdated_checker import OutdatedChecker
from sca.git_history import GitHistoryScanner

logger = get_logger(__name__)


def analyze(
    project_path: str,
    *,
    cache_dir: Optional[str] = None,
    config_file: Optional[str] = None,
    include_git_history: bool = False,
    max_history_commits: Optional[int] = None,
    history_since: Optional[str] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """
    Run full SCA analysis on a project directory.

    Parameters
    ----------
    project_path        : path to the project root directory
    cache_dir           : custom cache directory; defaults to config.CACHE_DIR
    config_file         : path to YAML configuration file (future)
    include_git_history : scan git history for deleted/modified files
    max_history_commits : limit number of commits to scan
    history_since       : only scan commits after this date (e.g. "2024-01-01")

    Returns
    -------
    dict with keys:
        status
        packages
        imports
        license_findings
        vendored_matches
        rule_findings
        vulnerabilities
        outdated
        history_findings (if include_git_history=True)
    """
    logger.info("Starting analysis", path=project_path)

    # 1. Dependency resolution
    registry = ResolverRegistry([
        NpmResolver(),
        PypiResolver(),
        MavenResolver(),
        GoResolver(),
    ])
    ecosystems = detect_manifests(project_path)
    packages = registry.resolve(project_path, ecosystems)

    # 2. File discovery (skip binary and minified for efficiency)
    all_files = discover_files(project_path, skip_binary=True, skip_minified=True)

    # 3. Import mapping
    imports = map_imports(all_files)

    # 4. License scan
    license_findings = []
    try:
        lic_scanner = LicenseScanner(cache_dir=cache_dir)
        license_findings = lic_scanner.scan_directory(project_path, file_paths=all_files)
    except Exception as e:
        logger.warning(f"License scanning failed: {e}")

    # 5. Vendored code scan
    vendored_findings = []
    try:
        vend_scanner = VendoredScanner(cache_dir=cache_dir)
        vendored_findings = vend_scanner.scan_directory(project_path, file_paths=all_files)
    except Exception as e:
        logger.warning(f"Vendored scanning failed: {e}")

    # 6. Rule scan (ast‑grep)
    rule_findings = []
    if HAS_AST_GREP:
        try:
            rule_scanner = RuleScanner(cache_dir=cache_dir)
            rule_findings = rule_scanner.scan_files(all_files)
        except Exception as e:
            logger.warning(f"Rule scanning failed: {e}")
    else:
        logger.info("ast-grep not available, skipping rule scan")

    # 7. Vulnerability mapping (needs local vulnerability database)
    vuln_findings = []
    try:
        mapper = VulnerabilityMapper()
        vuln_findings = mapper.map_packages(packages, imports)
    except Exception as e:
        logger.warning(f"Vulnerability mapping failed: {e}")

    # 8. Outdated dependency check
    outdated_findings = []
    try:
        checker = OutdatedChecker()
        outdated_findings = checker.check(packages, imports)
    except Exception as e:
        logger.warning(f"Outdated check failed: {e}")

    # 9. Git history scanning (optional)
    history_findings = []
    if include_git_history:
        try:
            git_scanner = GitHistoryScanner(
                project_path,
                cache_dir=cache_dir,
                max_commits=max_history_commits,
                since=history_since,
            )
            history_findings = [dataclasses.asdict(h) for h in git_scanner.scan()]
        except Exception as e:
            logger.warning(f"Git history scanning failed: {e}")

    result = {
        "status": "ok",
        "packages": [dataclasses.asdict(p) for p in packages],
        "imports": {k: v for k, v in imports.items()},  # tuple values -> list
        "license_findings": [dataclasses.asdict(f) for f in license_findings],
        "vendored_matches": [dataclasses.asdict(m) for m in vendored_findings],
        "rule_findings": [dataclasses.asdict(r) for r in rule_findings],
        "vulnerabilities": [dataclasses.asdict(v) for v in vuln_findings],
        "outdated": [dataclasses.asdict(o) for o in outdated_findings],
    }
    if include_git_history:
        result["history_findings"] = history_findings

    logger.info("Analysis complete", path=project_path)
    return result


# Expose public API
__all__ = ["analyze"]
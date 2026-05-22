"""Software Composition Analysis Toolkit – Main entry point with monorepo support."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any, Dict, List, Optional

from sca.utils import get_logger

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
    """Analyze a project for dependencies, licenses, and vulnerabilities."""
    # Lazy import to avoid hanging on module load
    from sca.ecosystem import detect_sub_projects, detect_manifests
    from sca.resolver.plugin import discover_plugins, get_all_resolvers
    from sca.resolver.registry import ResolverRegistry
    from sca.git_history import GitHistoryScanner
    
    logger.info("Starting analysis", path=project_path)

    # Load resolver plugins
    discover_plugins()
    resolvers = get_all_resolvers()
    if not resolvers:
        from sca.resolver.plugins.npm import NpmResolver
        from sca.resolver.plugins.pypi import PypiResolver
        from sca.resolver.plugins.maven import MavenResolver
        from sca.resolver.plugins.go import GoResolver
        resolvers = [NpmResolver(), PypiResolver(), MavenResolver(), GoResolver()]
    registry = ResolverRegistry(resolvers)

    # Detect sub-projects (monorepo) unless disabled
    if kwargs.get('no_subprojects'):
        sub_projects = [Path(project_path).resolve()]
    else:
        sub_projects = detect_sub_projects(project_path)
        if not sub_projects:
            sub_projects = [Path(project_path).resolve()]

    all_results = []
    for sub_project in sub_projects:
        logger.info("Analyzing sub-project", path=str(sub_project))
        sub_result = _analyze_single(
            project_path=str(sub_project),
            registry=registry,
            cache_dir=cache_dir,
        )
        sub_result["project_path"] = str(sub_project)
        all_results.append(sub_result)

    # Git history (on root)
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

    return {
        "status": "ok",
        "sub_projects": all_results,
        "history_findings": history_findings,
    }


def _analyze_single(
    project_path: str,
    registry: Any,
    cache_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """Analyze a single project (non-monorepo or individual sub-project)."""
    # Lazy imports
    from sca.ecosystem import detect_manifests
    from sca.file_hasher import discover_files
    from sca.import_mapper import map_imports
    from sca.scanners import LicenseScanner, VendoredScanner
    from sca.rule_scanner import RuleScanner, HAS_AST_GREP
    from sca.vulnerability_mapper import VulnerabilityMapper
    from sca.outdated_checker import OutdatedChecker
    
    # 1. Dependency resolution
    ecosystems = detect_manifests(project_path)
    packages = registry.resolve(project_path, ecosystems)

    # 2. File discovery
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

    # 5. Vendored scan
    vendored_findings = []
    try:
        vend_scanner = VendoredScanner(cache_dir=cache_dir)
        vendored_findings = vend_scanner.scan_directory(project_path, file_paths=all_files)
    except Exception as e:
        logger.warning(f"Vendored scanning failed: {e}")

    # 6. Rule scan
    rule_findings = []
    if HAS_AST_GREP:
        try:
            rule_scanner = RuleScanner(cache_dir=cache_dir)
            rule_findings = rule_scanner.scan_files(all_files)
        except Exception as e:
            logger.warning(f"Rule scanning failed: {e}")

    # 7. Vulnerability mapping
    vuln_findings = []
    try:
        mapper = VulnerabilityMapper()
        vuln_findings = mapper.map_packages(packages, imports)
    except Exception as e:
        logger.warning(f"Vulnerability mapping failed: {e}")

    # 8. Outdated check
    outdated_findings = []
    try:
        checker = OutdatedChecker()
        outdated_findings = checker.check(packages, imports)
    except Exception as e:
        logger.warning(f"Outdated check failed: {e}")

    return {
        "packages": [dataclasses.asdict(p) for p in packages],
        "imports": {k: v for k, v in imports.items()},
        "license_findings": [dataclasses.asdict(f) for f in license_findings],
        "vendored_matches": [dataclasses.asdict(m) for m in vendored_findings],
        "rule_findings": [dataclasses.asdict(r) for r in rule_findings],
        "vulnerabilities": [dataclasses.asdict(v) for v in vuln_findings],
        "outdated": [dataclasses.asdict(o) for o in outdated_findings],
    }
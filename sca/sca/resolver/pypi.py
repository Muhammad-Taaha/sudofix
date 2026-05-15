"""Resolve Python dependencies from requirements.txt, poetry.lock, Pipfile.lock, setup.py/setup.cfg."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import requirements
import toml

from sca.resolver.base import DependencyResolver, ResolvedPackage
from sca.utils import get_logger

logger = get_logger(__name__)


class PypiResolver(DependencyResolver):
    ecosystem = "pypi"

    def can_handle(self, manifest_paths: List[str]) -> bool:
        return any(
            Path(p).name in {"requirements.txt", "poetry.lock", "Pipfile.lock", "setup.py", "setup.cfg"}
            for p in manifest_paths
        )

    def resolve(self, project_path: str) -> List[ResolvedPackage]:
        root = Path(project_path).resolve()
        packages: Dict[str, ResolvedPackage] = {}

        # 1. Parse poetry.lock (if present)
        poetry_locks = sorted(root.rglob("poetry.lock"))
        for lock_path in poetry_locks:
            try:
                packages.update(self._parse_poetry_lock(lock_path))
            except Exception as e:
                logger.warning("Failed to parse poetry.lock", path=str(lock_path), error=str(e))

        # 2. Parse Pipfile.lock
        pipfile_locks = sorted(root.rglob("Pipfile.lock"))
        for lock_path in pipfile_locks:
            try:
                packages.update(self._parse_pipfile_lock(lock_path))
            except Exception as e:
                logger.warning("Failed to parse Pipfile.lock", path=str(lock_path), error=str(e))

        # 3. Parse requirements.txt files
        req_files = sorted(root.rglob("requirements*.txt"))
        for req_path in req_files:
            try:
                packages.update(self._parse_requirements(req_path))
            except Exception as e:
                logger.warning("Failed to parse requirements.txt", path=str(req_path), error=str(e))

        # 4. If we still have no results, try pip install --dry-run --report for setup.py/setup.cfg
        setup_files = list(root.rglob("setup.py")) + list(root.rglob("setup.cfg"))
        if setup_files and not packages:
            try:
                packages.update(self._resolve_via_pip_report(root))
            except Exception as e:
                logger.warning("Failed to run pip install --dry-run", error=str(e))

        # Mark direct dependencies based on manifest presence
        direct_names = self._collect_direct_names(root)
        for pkg in packages.values():
            if pkg.name in direct_names:
                pkg.is_direct = True

        logger.info("PyPI resolution complete", total_packages=len(packages))
        return list(packages.values())

    def _parse_requirements(self, path: Path) -> Dict[str, ResolvedPackage]:
        results = {}
        with open(path, "r", encoding="utf-8") as f:
            for req in requirements.parse(f):
                if req.name and req.specs:
                    # Use the first version spec as the version (best-effort)
                    version = req.specs[0][1] if req.specs else "unknown"
                    key = f"{req.name}@{version}"
                    if key not in results:
                        results[key] = ResolvedPackage(
                            name=req.name,
                            version=version,
                            ecosystem="pypi",
                            is_direct=False,
                            resolved_from=str(path),
                        )
        return results

    def _parse_poetry_lock(self, path: Path) -> Dict[str, ResolvedPackage]:
        data = toml.load(path)
        results = {}
        for pkg in data.get("package", []):
            name = pkg.get("name")
            version = pkg.get("version", "unknown")
            if not name:
                continue
            key = f"{name}@{version}"
            if key in results:
                continue
            deps = set()
            if "dependencies" in pkg:
                # poetry uses a dict of name->version, but we just need names
                deps = set(pkg["dependencies"].keys())
            results[key] = ResolvedPackage(
                name=name,
                version=version,
                ecosystem="pypi",
                is_direct=False,
                dependencies=deps,
                resolved_from=str(path),
            )
        return results

    def _parse_pipfile_lock(self, path: Path) -> Dict[str, ResolvedPackage]:
        data = toml.load(path)
        results = {}
        for section in ("default", "develop"):
            for name, info in data.get(section, {}).items():
                version = info.get("version", "unknown") if isinstance(info, dict) else str(info)
                # Remove leading '==' if present
                version = version.lstrip("=")
                key = f"{name}@{version}"
                if key in results:
                    continue
                deps = set()
                # Pipfile doesn't list transitive deps; ignore
                results[key] = ResolvedPackage(
                    name=name,
                    version=version,
                    ecosystem="pypi",
                    is_direct=(section == "default"),
                    resolved_from=str(path),
                )
        return results

    def _resolve_via_pip_report(self, project_dir: Path) -> Dict[str, ResolvedPackage]:
        """Run `pip install --dry-run --report` in a temporary venv and parse the JSON report."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cmd = [
                "pip", "install",
                "--dry-run",
                "--report", str(Path(tmpdir) / "report.json"),
                "--no-cache-dir",
                str(project_dir),
            ]
            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=True)
                report_path = Path(tmpdir) / "report.json"
                if report_path.exists():
                    with open(report_path, "r") as f:
                        report = json.load(f)
                    results = {}
                    for pkg in report.get("install", []):
                        metadata = pkg.get("metadata", {})
                        name = metadata.get("name")
                        version = metadata.get("version", "unknown")
                        if name:
                            key = f"{name}@{version}"
                            if key not in results:
                                results[key] = ResolvedPackage(
                                    name=name,
                                    version=version,
                                    ecosystem="pypi",
                                    is_direct=False,
                                    resolved_from="pip-report",
                                )
                    return results
            except Exception:
                pass
        return {}

    def _collect_direct_names(self, root: Path) -> Set[str]:
        """Return names of all packages listed in requirements.txt or [tool.poetry.dependencies]."""
        names = set()
        for req_file in root.rglob("requirements*.txt"):
            try:
                with open(req_file, "r") as f:
                    for req in requirements.parse(f):
                        if req.name:
                            names.add(req.name)
            except Exception:
                pass
        # poetry.toml for direct deps
        pyproject = root / "pyproject.toml"
        if pyproject.exists():
            try:
                data = toml.load(pyproject)
                deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
                if isinstance(deps, dict):
                    for name in deps:
                        if name.lower() != "python":
                            names.add(name)
            except Exception:
                pass
        return names
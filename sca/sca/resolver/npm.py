"""Resolve npm dependencies from package-lock.json and yarn.lock."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from sca.resolver.base import DependencyResolver, ResolvedPackage
from sca.utils import get_logger

logger = get_logger(__name__)


class NpmResolver(DependencyResolver):
    ecosystem = "npm"

    def can_handle(self, manifest_paths: List[str]) -> bool:
        for p in manifest_paths:
            fname = Path(p).name
            if fname in {"package-lock.json", "yarn.lock", "package.json"}:
                return True
        return False

    def resolve(self, project_path: str) -> List[ResolvedPackage]:
        root = Path(project_path).resolve()
        packages: Dict[str, ResolvedPackage] = {}

        # 1. Collect package.json files (excluding node_modules)
        package_jsons = sorted(root.rglob("package.json"))
        package_jsons = [p for p in package_jsons if "node_modules" not in p.parts]

        # 2. Process package-lock.json files
        lock_paths = list(root.rglob("package-lock.json"))
        for lock_path in lock_paths:
            if "node_modules" in lock_path.parts:
                continue
            try:
                parsed = self._parse_package_lock(lock_path)
                packages.update(parsed)
                logger.debug("Parsed package-lock.json", path=str(lock_path), count=len(parsed))
            except Exception as e:
                logger.warning("Failed to parse package-lock.json", path=str(lock_path), error=str(e))

        # 3. Process yarn.lock files
        yarn_lock_paths = list(root.rglob("yarn.lock"))
        for ylock_path in yarn_lock_paths:
            if "node_modules" in ylock_path.parts:
                continue
            try:
                parsed = self._parse_yarn_lock(ylock_path)
                packages.update(parsed)
                logger.debug("Parsed yarn.lock", path=str(ylock_path), count=len(parsed))
            except Exception as e:
                logger.warning("Failed to parse yarn.lock", path=str(ylock_path), error=str(e))

        # 4. Mark direct dependencies using package.json files
        direct_names = self._collect_workspace_direct(package_jsons)
        for pkg in packages.values():
            if pkg.name in direct_names:
                pkg.is_direct = True

        logger.info("NPM resolution complete", total_packages=len(packages))
        return list(packages.values())

    def _parse_package_lock(self, lock_path: Path) -> Dict[str, ResolvedPackage]:
        with open(lock_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        results: Dict[str, ResolvedPackage] = {}
        if "packages" in data:
            # v2/v3 format
            for pkg_path, info in data["packages"].items():
                if not pkg_path:
                    continue
                name = info.get("name") or self._extract_name_from_path(pkg_path)
                version = str(info.get("version", "unknown"))
                key = f"{name}@{version}"
                if key in results:
                    continue
                dependencies = self._extract_dependencies(info)
                pkg = ResolvedPackage(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    is_direct=False,
                    dependencies=dependencies,
                    resolved_from=str(lock_path),
                )
                results[key] = pkg
        elif "dependencies" in data:
            # v1 format
            for name, info in data["dependencies"].items():
                version = str(info.get("version", "unknown"))
                key = f"{name}@{version}"
                if key in results:
                    continue
                requires = info.get("requires", {})
                if isinstance(requires, dict):
                    deps = set(requires.keys())
                else:
                    deps = set()
                pkg = ResolvedPackage(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    is_direct=False,
                    dependencies=deps,
                    resolved_from=str(lock_path),
                )
                results[key] = pkg
        return results

    def _parse_yarn_lock(self, lock_path: Path) -> Dict[str, ResolvedPackage]:
        with open(lock_path, "r", encoding="utf-8") as f:
            content = f.read()

        entries = self._split_yarn_entries(content)
        results: Dict[str, ResolvedPackage] = {}
        for entry in entries:
            name, _ = self._parse_yarn_header(entry["header"])
            version = self._parse_yarn_entry_body_for_version(entry["body"])
            if not name or not version:
                continue
            key = f"{name}@{version}"
            if key in results:
                continue
            deps = set()
            for line in entry["body"].splitlines():
                dep_match = re.match(r'^\s+"?([^@"\s]+)@[^:]*"?:\s*"(.*)"', line)
                if dep_match:
                    deps.add(dep_match.group(1))
            pkg = ResolvedPackage(
                name=name,
                version=version,
                ecosystem="npm",
                is_direct=False,
                dependencies=deps,
                resolved_from=str(lock_path),
            )
            results[key] = pkg
        return results

    def _split_yarn_entries(self, content: str) -> List[Dict[str, str]]:
        entries = []
        current_header = None
        current_body_lines = []
        for line in content.splitlines():
            if not line.strip():
                continue
            if line.startswith("#") or line.startswith("__"):
                continue
            if not line[0].isspace() and ":" in line and not line.strip().startswith("resolved "):
                if current_header is not None:
                    entries.append({"header": current_header, "body": "\n".join(current_body_lines)})
                current_header = line.rstrip(":")
                current_body_lines = []
            else:
                if current_header is not None:
                    current_body_lines.append(line)
        if current_header is not None:
            entries.append({"header": current_header, "body": "\n".join(current_body_lines)})
        return entries

    def _parse_yarn_header(self, header: str) -> Tuple[Optional[str], Optional[str]]:
        header = header.strip().strip('"')
        # Handle scoped packages: @scope/name@version
        match = re.match(r'^"?(@?[^@]+)@(.+)"?$', header)
        if match:
            return match.group(1), None  # version extracted from body later
        # fallback for scoped packages with multiple @
        if header.startswith("@"):
            parts = header.split("@", 2)
            if len(parts) == 3:
                name = f"@{parts[1]}"
                return name, None
        return None, None

    def _parse_yarn_entry_body_for_version(self, body: str) -> Optional[str]:
        for line in body.splitlines():
            m = re.match(r'^\s*version\s+"?([^"]+)"?', line)
            if m:
                return m.group(1)
        return None

    def _collect_workspace_direct(self, package_jsons: List[Path]) -> Set[str]:
        """Return a set of package names that are direct dependencies (from any workspace package.json)."""
        direct_names: Set[str] = set()
        for pj_path in package_jsons:
            try:
                data = json.loads(pj_path.read_text(encoding="utf-8"))
            except Exception:
                continue
            for field in ("dependencies", "devDependencies", "peerDependencies"):
                deps = data.get(field, {})
                if isinstance(deps, dict):
                    for name in deps.keys():
                        direct_names.add(name)
        return direct_names

    def _extract_name_from_path(self, pkg_path: str) -> str:
        """Extract package name from a node_modules path like 'node_modules/foo' or 'node_modules/foo/bar'."""
        # Normalize path separators
        pkg_path = pkg_path.replace("\\", "/")
        parts = pkg_path.split("/")
        if "node_modules" in parts:
            idx = parts.index("node_modules")
            if idx + 1 < len(parts):
                return parts[idx + 1]
        # Fallback: last part
        return parts[-1]

    @staticmethod
    def _extract_dependencies(info: Dict[str, Any]) -> Set[str]:
        """Extract dependency names from the package info dict."""
        deps = info.get("dependencies", {})
        if isinstance(deps, dict):
            return set(deps.keys())
        return set()
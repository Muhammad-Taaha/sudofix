"""Rust Cargo.lock resolver."""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Dict

from sca.resolver.base import DependencyResolver, ResolvedPackage
from sca.resolver.plugin import register_resolver
from sca.utils import get_logger

logger = get_logger(__name__)

# Cargo.lock format: [[package]] name = "...", version = "..."
PACKAGE_RE = re.compile(r'^name\s*=\s*"([^"]+)"\s*$')
VERSION_RE = re.compile(r'^version\s*=\s*"([^"]+)"\s*$')


class RustResolver(DependencyResolver):
    ecosystem = "rust"

    def can_handle(self, manifest_paths: List[str]) -> bool:
        return any(Path(p).name in {"Cargo.lock", "Cargo.toml"} for p in manifest_paths)

    def resolve(self, project_path: str) -> List[ResolvedPackage]:
        root = Path(project_path).resolve()
        packages = {}
        for lock_file in root.rglob("Cargo.lock"):
            if "target" in lock_file.parts:
                continue
            try:
                text = lock_file.read_text()
                # Simple state machine: when we see [[package]], read name/version
                current_package = {}
                for line in text.splitlines():
                    line = line.strip()
                    if line.startswith("[["):
                        # Save previous package
                        if current_package.get("name") and current_package.get("version"):
                            name = current_package["name"]
                            version = current_package["version"]
                            key = f"{name}@{version}"
                            if key not in packages:
                                packages[key] = ResolvedPackage(
                                    name=name,
                                    version=version,
                                    ecosystem="rust",
                                    is_direct=False,
                                    resolved_from=str(lock_file),
                                )
                        current_package = {}
                    else:
                        name_match = PACKAGE_RE.match(line)
                        if name_match:
                            current_package["name"] = name_match.group(1)
                        version_match = VERSION_RE.match(line)
                        if version_match:
                            current_package["version"] = version_match.group(1)
                # Don't forget the last package
                if current_package.get("name") and current_package.get("version"):
                    name = current_package["name"]
                    version = current_package["version"]
                    key = f"{name}@{version}"
                    if key not in packages:
                        packages[key] = ResolvedPackage(
                            name=name,
                            version=version,
                            ecosystem="rust",
                            is_direct=False,
                            resolved_from=str(lock_file),
                        )
            except Exception as e:
                logger.warning(f"Failed to parse {lock_file}: {e}")
        return list(packages.values())


register_resolver("rust", RustResolver)
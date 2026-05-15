""".NET resolver – parses packages.config (NuGet)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import List

from sca.resolver.base import DependencyResolver, ResolvedPackage
from sca.resolver.plugin import register_resolver
from sca.utils import get_logger

logger = get_logger(__name__)

# packages.config: <package id="Newtonsoft.Json" version="13.0.1" targetFramework="net48" />
PACKAGE_RE = re.compile(r'id="([^"]+)"\s+version="([^"]+)"')


class DotnetResolver(DependencyResolver):
    ecosystem = "dotnet"

    def can_handle(self, manifest_paths: List[str]) -> bool:
        return any(Path(p).name == "packages.config" for p in manifest_paths)

    def resolve(self, project_path: str) -> List[ResolvedPackage]:
        root = Path(project_path).resolve()
        packages = {}
        for pkg_config in root.rglob("packages.config"):
            try:
                text = pkg_config.read_text()
                for m in PACKAGE_RE.finditer(text):
                    name = m.group(1)
                    version = m.group(2)
                    key = f"{name}@{version}"
                    if key not in packages:
                        packages[key] = ResolvedPackage(
                            name=name,
                            version=version,
                            ecosystem="dotnet",
                            is_direct=False,
                            resolved_from=str(pkg_config),
                        )
            except Exception as e:
                logger.warning(f"Failed to parse {pkg_config}: {e}")
        return list(packages.values())


register_resolver("dotnet", DotnetResolver)
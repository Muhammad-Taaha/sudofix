"""Swift Package Manager resolver (Package.resolved)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Dict

from sca.resolver.base import DependencyResolver, ResolvedPackage
from sca.resolver.plugin import register_resolver
from sca.utils import get_logger

logger = get_logger(__name__)


class SwiftResolver(DependencyResolver):
    ecosystem = "swift"

    def can_handle(self, manifest_paths: List[str]) -> bool:
        return any(Path(p).name == "Package.resolved" for p in manifest_paths)

    def resolve(self, project_path: str) -> List[ResolvedPackage]:
        root = Path(project_path).resolve()
        packages = {}
        for resolved_file in root.rglob("Package.resolved"):
            if ".build" in resolved_file.parts:
                continue
            try:
                data = json.loads(resolved_file.read_text())
                for pin in data.get("pins", []):
                    name = pin.get("identity", pin.get("package", ""))
                    version = pin.get("state", {}).get("version", "unknown")
                    key = f"{name}@{version}"
                    if key not in packages:
                        packages[key] = ResolvedPackage(
                            name=name,
                            version=version,
                            ecosystem="swift",
                            is_direct=False,
                            resolved_from=str(resolved_file),
                        )
            except Exception as e:
                logger.warning(f"Failed to parse {resolved_file}: {e}")
        return list(packages.values())


register_resolver("swift", SwiftResolver)
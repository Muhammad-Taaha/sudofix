"""Resolve Go dependencies from go.mod and go.sum."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Set, Tuple

from sca.resolver.base import DependencyResolver, ResolvedPackage
from sca.utils import get_logger

logger = get_logger(__name__)

# go.mod: module path and require blocks
MOD_REGEX = re.compile(r"^\s*module\s+(\S+)")
REQUIRE_REGEX = re.compile(r"^\s*(\S+)\s+(v[\w\.\+-]+)")
# go.sum: <module> <version> <hash>
SUM_REGEX = re.compile(r"^(\S+)\s+(v[\w\.\+-]+)\s+(\S+)")


class GoResolver(DependencyResolver):
    ecosystem = "go"

    def can_handle(self, manifest_paths: List[str]) -> bool:
        return any(Path(p).name in {"go.mod", "go.sum"} for p in manifest_paths)

    def resolve(self, project_path: str) -> List[ResolvedPackage]:
        root = Path(project_path).resolve()
        packages: Dict[str, ResolvedPackage] = {}

        # Find all go.mod / go.sum pairs
        for go_mod in root.rglob("go.mod"):
            mod_dir = go_mod.parent
            go_sum = mod_dir / "go.sum"

            direct_deps: Set[str] = set()
            # Parse go.mod for direct requirements
            try:
                with open(go_mod, "r", encoding="utf-8") as f:
                    content = f.read()
                in_require_block = False
                for line in content.splitlines():
                    # Detect require block start/end
                    if line.strip().startswith("require ("):
                        in_require_block = True
                        continue
                    if in_require_block:
                        if line.strip() == ")":
                            in_require_block = False
                            continue
                        m = REQUIRE_REGEX.match(line)
                        if m:
                            module_path = m.group(1)
                            version = m.group(2)
                            direct_deps.add(module_path)
                    else:
                        m = REQUIRE_REGEX.match(line)
                        if m:
                            module_path = m.group(1)
                            version = m.group(2)
                            direct_deps.add(module_path)
            except Exception as e:
                logger.warning("Failed to parse go.mod", path=str(go_mod), error=str(e))

            # Parse go.sum for concrete versions of all modules (direct + transitive)
            try:
                with open(go_sum, "r", encoding="utf-8") as f:
                    for line in f:
                        m = SUM_REGEX.match(line)
                        if m:
                            module_path = m.group(1)
                            version = m.group(2)
                            key = f"{module_path}@{version}"
                            if key not in packages:
                                packages[key] = ResolvedPackage(
                                    name=module_path,
                                    version=version,
                                    ecosystem="go",
                                    is_direct=module_path in direct_deps,
                                    dependencies=set(),  # go.sum doesn't show deps
                                    resolved_from=str(go_sum),
                                )
            except Exception as e:
                logger.warning("Failed to parse go.sum", path=str(go_sum), error=str(e))

            # If no go.sum, use go.mod versions as resolved (best-effort)
            if not packages:
                for mod_path, version in direct_deps:
                    key = f"{mod_path}@{version}"
                    packages[key] = ResolvedPackage(
                        name=mod_path,
                        version=version,
                        ecosystem="go",
                        is_direct=True,
                        dependencies=set(),
                        resolved_from=str(go_mod),
                    )

        logger.info("Go resolution complete", total_packages=len(packages))
        return list(packages.values())
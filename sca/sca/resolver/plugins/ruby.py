"""Ruby resolver – parses Gemfile.lock."""

from __future__ import annotations

import re
from pathlib import Path
from typing import List

from sca.resolver.base import DependencyResolver, ResolvedPackage
from sca.resolver.plugin import register_resolver
from sca.utils import get_logger

logger = get_logger(__name__)

# Gemfile.lock format:
#   GEM
#     remote: ...
#     specs:
#       gem_name (version)
#       gem_name (version-dependency)
#   PLATFORMS
#   DEPENDENCIES
#   ...

GEM_SPEC_RE = re.compile(r"^\s{4}(\S+)\s*\(([^)]+)\)")


class RubyResolver(DependencyResolver):
    ecosystem = "ruby"

    def can_handle(self, manifest_paths: List[str]) -> bool:
        return any(Path(p).name == "Gemfile.lock" for p in manifest_paths)

    def resolve(self, project_path: str) -> List[ResolvedPackage]:
        root = Path(project_path).resolve()
        packages = {}
        for lockfile in root.rglob("Gemfile.lock"):
            try:
                text = lockfile.read_text()
                in_specs = False
                for line in text.splitlines():
                    if line.strip() == "specs:":
                        in_specs = True
                        continue
                    if in_specs and not line.startswith("    "):
                        in_specs = False
                        continue
                    if in_specs:
                        m = GEM_SPEC_RE.match(line)
                        if m:
                            name = m.group(1)
                            version = m.group(2).split("-")[0]  # remove dependency suffix
                            key = f"{name}@{version}"
                            if key not in packages:
                                packages[key] = ResolvedPackage(
                                    name=name,
                                    version=version,
                                    ecosystem="ruby",
                                    is_direct=False,
                                    resolved_from=str(lockfile),
                                )
            except Exception as e:
                logger.warning(f"Failed to parse {lockfile}: {e}")
        return list(packages.values())


register_resolver("ruby", RubyResolver)
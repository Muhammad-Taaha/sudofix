"""Registry that runs all applicable resolvers in parallel."""

from __future__ import annotations

import concurrent.futures
from typing import Dict, List

from sca.resolver.base import DependencyResolver, ResolvedPackage
from sca.utils import get_logger

logger = get_logger(__name__)


class ResolverRegistry:
    def __init__(self, resolvers: List[DependencyResolver]):
        self.resolvers = resolvers

    def resolve(self, project_path: str, ecosystem_files: Dict[str, List[str]]) -> List[ResolvedPackage]:
        all_packages: Dict[str, ResolvedPackage] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(self.resolvers)) as executor:
            futures = {
                executor.submit(self._run_resolver, resolver, project_path, ecosystem_files): resolver
                for resolver in self.resolvers
            }
            for future in concurrent.futures.as_completed(futures):
                resolver = futures[future]
                try:
                    pkgs = future.result()
                    for p in pkgs:
                        key = f"{p.name}@{p.version}@{p.ecosystem}"
                        if key not in all_packages:
                            all_packages[key] = p
                        else:
                            # merge dependencies and dependents if needed
                            existing = all_packages[key]
                            existing.dependencies.update(p.dependencies)
                            existing.is_direct = existing.is_direct or p.is_direct
                except Exception as e:
                    logger.error("Resolver failed", ecosystem=resolver.ecosystem, error=str(e))
        return list(all_packages.values())

    def _run_resolver(self, resolver: DependencyResolver, project_path: str, ecosystem_files: Dict[str, List[str]]) -> List[ResolvedPackage]:
        if not resolver.can_handle(ecosystem_files.get(resolver.ecosystem, [])):
            return []
        return resolver.resolve(project_path)
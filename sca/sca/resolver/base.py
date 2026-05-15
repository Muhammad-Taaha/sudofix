from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class ResolvedPackage:
    """Represents a resolved dependency."""

    name: str
    version: str
    ecosystem: str  # npm, pypi, maven, go, etc.
    is_direct: bool = False
    dependents: Set[str] = field(default_factory=set)  # packages that depend on this one
    dependencies: Set[str] = field(default_factory=set)  # packages this one depends on
    resolved_from: Optional[str] = None  # lockfile path or manifest
    optional: bool = False
    dev: bool = False

    def __hash__(self):
        return hash((self.name, self.version, self.ecosystem))

    def __eq__(self, other):
        if not isinstance(other, ResolvedPackage):
            return False
        return (self.name, self.version, self.ecosystem) == (other.name, other.version, other.ecosystem)


class DependencyResolver:
    """Base class for ecosystem-specific resolvers."""

    ecosystem: str

    def can_handle(self, manifest_paths: List[str]) -> bool:
        """Return True if this resolver should be used."""
        return False

    def resolve(self, project_path: str) -> List[ResolvedPackage]:
        """Extract all dependencies from lockfiles/manifests."""
        raise NotImplementedError
"""Plugin base and discovery mechanism for dependency resolvers."""

from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path
from typing import Dict, List, Type

from sca.resolver.base import DependencyResolver, ResolvedPackage
from sca.utils import get_logger

logger = get_logger(__name__)

# Registry maps ecosystem name -> resolver class
_RESOLVER_REGISTRY: Dict[str, Type[DependencyResolver]] = {}


def register_resolver(ecosystem: str, resolver_cls: Type[DependencyResolver]):
    """Register a resolver class for a specific ecosystem."""
    _RESOLVER_REGISTRY[ecosystem] = resolver_cls


def discover_plugins(package_path: str = "sca.resolver.plugins"):
    """Import all modules in the plugins package to trigger registration."""
    package = importlib.import_module(package_path)
    for _, module_name, _ in pkgutil.iter_modules(package.__path__, package.__name__ + "."):
        importlib.import_module(module_name)
    logger.info(f"Loaded resolver plugins: {list(_RESOLVER_REGISTRY.keys())}")


def get_resolver(ecosystem: str) -> DependencyResolver:
    """Return an instance of the resolver for the given ecosystem, or None."""
    cls = _RESOLVER_REGISTRY.get(ecosystem)
    if cls:
        return cls()
    return None


def get_all_resolvers() -> List[DependencyResolver]:
    """Return instances of all registered resolvers."""
    return [cls() for cls in _RESOLVER_REGISTRY.values()]
"""Detect ecosystem manifest/lockfile pairs in a project directory."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Tuple

from sca.utils import get_logger

logger = get_logger(__name__)

# Mapping of file patterns to ecosystem name and whether it's a manifest or lockfile
ECOSYSTEM_MANIFESTS: Dict[str, Tuple[str, str]] = {
    "package.json": ("npm", "manifest"),
    "package-lock.json": ("npm", "lock"),
    "yarn.lock": ("npm", "lock"),
    "requirements.txt": ("pypi", "manifest"),
    "poetry.lock": ("pypi", "lock"),
    "Pipfile.lock": ("pypi", "lock"),
    "setup.py": ("pypi", "manifest"),
    "setup.cfg": ("pypi", "manifest"),
    "pom.xml": ("maven", "manifest"),
    "go.mod": ("go", "manifest"),
    "go.sum": ("go", "lock"),
    "Cargo.lock": ("rust", "lock"),
    "Cargo.toml": ("rust", "manifest"),
    "Package.resolved": ("swift", "lock"),
}


def detect_manifests(root_dir: str | Path) -> Dict[str, List[str]]:
    """
    Walk the directory tree, find all recognized manifests/lockfiles, and group them by ecosystem.

    Returns: dict like {"npm": ["path/package.json", "path/package-lock.json"], "pypi": [...], ...}
    """
    root = Path(root_dir).resolve()
    ecosystem_files: Dict[str, List[str]] = {}

    for dirpath, _, filenames in os.walk(root):
        for fname in filenames:
            if fname in ECOSYSTEM_MANIFESTS:
                eco, _ = ECOSYSTEM_MANIFESTS[fname]
                full_path = str(Path(dirpath) / fname)
                ecosystem_files.setdefault(eco, []).append(full_path)

    # Remove ecosystems that have no lockfile (except for ecosystems where manifest is sufficient)
    # For now, keep all; resolvers will decide.
    logger.debug("Detected manifest files", ecosystems=list(ecosystem_files.keys()))
    return ecosystem_files
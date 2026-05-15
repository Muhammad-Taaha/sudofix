"""Detect ecosystem manifests and sub‑project directories in a repository."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Tuple

from sca.utils import get_logger

logger = get_logger(__name__)

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
    "Gemfile.lock": ("ruby", "lock"),
    "packages.config": ("dotnet", "manifest"),
}

MANIFEST_FILENAMES = set(ECOSYSTEM_MANIFESTS.keys())


def detect_manifests(root_dir: str | Path) -> Dict[str, List[str]]:
    """Return ecosystem -> list of manifest/lockfile paths."""
    root = Path(root_dir).resolve()
    ecosystem_files: Dict[str, List[str]] = {}

    for dirpath, _, filenames in os.walk(root):
        for fname in filenames:
            if fname in ECOSYSTEM_MANIFESTS:
                eco, _ = ECOSYSTEM_MANIFESTS[fname]
                full_path = str(Path(dirpath) / fname)
                ecosystem_files.setdefault(eco, []).append(full_path)
    return ecosystem_files


def detect_sub_projects(root_dir: str | Path) -> List[Path]:
    """
    Find all directories that contain at least one recognized manifest/lockfile.
    Returns a list of absolute paths sorted depth‑first (deepest first) so that
    outer projects can be identified if needed.
    """
    root = Path(root_dir).resolve()
    dirs_with_manifests = set()
    for dirpath, _, filenames in os.walk(root):
        if any(f in MANIFEST_FILENAMES for f in filenames):
            dirs_with_manifests.add(Path(dirpath).resolve())
    # Sort by path depth descending so inner projects come first (optional)
    return sorted(dirs_with_manifests, key=lambda p: len(p.relative_to(root).parts), reverse=True)
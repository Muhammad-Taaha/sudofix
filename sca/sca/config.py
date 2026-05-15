"""
Default configuration constants and helpers.
"""

import os
import tempfile
from pathlib import Path
from typing import List

# Cache directory – uses XDG_CACHE_HOME if available, else a temp fallback
DEFAULT_CACHE_DIR = os.environ.get(
    "SCA_CACHE_DIR",
    os.path.join(
        os.environ.get("XDG_CACHE_HOME", os.path.join(Path.home(), ".cache")),
        "sca",
    ),
)

# Default ignore patterns (overridden by .gitignore and custom config)
DEFAULT_IGNORE_PATTERNS: List[str] = [
    ".git",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".gitignore",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "bower_components",
    "vendor",
    "dist",
    "build",
    "target",  # Rust / Java
    "out",  # Java
    "*.pyc",
    "*.pyo",
    "*.egg-info",
    "*.egg",
    ".tox",
    ".nox",
]

# Timeouts (seconds)
DEFAULT_FILE_READ_TIMEOUT = 5
DEFAULT_HASHING_WORKERS = os.cpu_count() or 4
DEFAULT_MAX_FILE_SIZE_MB = 100  # skip files larger than this

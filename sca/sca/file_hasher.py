"""
File discovery, filtering, and SHA‑256 hashing.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import os
from pathlib import Path
from typing import List, Optional, Tuple, Union

import pathspec

from sca.config import DEFAULT_HASHING_WORKERS, DEFAULT_IGNORE_PATTERNS, DEFAULT_MAX_FILE_SIZE_MB
from sca.utils import get_logger

logger = get_logger(__name__)


def _read_gitignore_patterns(root_dir: Path) -> Optional[pathspec.PathSpec]:
    """Parse .gitignore file and return a pathspec object, or None."""
    gitignore_path = root_dir / ".gitignore"
    if not gitignore_path.is_file():
        return None
    try:
        lines = gitignore_path.read_text(encoding="utf-8").splitlines()
        return pathspec.PathSpec.from_lines("gitwildmatch", lines)
    except Exception:
        logger.warning("Failed to parse .gitignore, ignoring", path=str(gitignore_path))
        return None


def discover_files(
    root_dir: Union[str, Path],
    *,
    ignore_patterns: Optional[List[str]] = None,
    max_file_size_mb: Optional[float] = DEFAULT_MAX_FILE_SIZE_MB,
    skip_binary: bool = False,
    skip_minified: bool = False,
) -> List[Path]:
    root = Path(root_dir).resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {root}")

    gitignore_spec = _read_gitignore_patterns(root)
    all_patterns = DEFAULT_IGNORE_PATTERNS + (ignore_patterns or [])
    combined_spec = pathspec.PathSpec.from_lines("gitwildmatch", all_patterns)

    max_size_bytes = None
    if max_file_size_mb is not None:
        max_size_bytes = int(max_file_size_mb * 1024 * 1024)

    files: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune ignored directories
        dir_rel = Path(dirpath).relative_to(root).as_posix()
        if dir_rel != "." and combined_spec.match_file(dir_rel):
            dirnames.clear()
            continue

        filtered_dirs = [
            d for d in dirnames
            if not combined_spec.match_file((Path(dirpath) / d).relative_to(root).as_posix())
        ]
        dirnames[:] = filtered_dirs

        for fname in filenames:
            fpath = Path(dirpath) / fname
            rel_path = fpath.relative_to(root).as_posix()

            if gitignore_spec and gitignore_spec.match_file(rel_path):
                continue
            if combined_spec.match_file(rel_path):
                continue

            # Size check
            if max_size_bytes is not None:
                try:
                    if fpath.stat().st_size > max_size_bytes:
                        logger.debug("Skipping large file", path=str(fpath))
                        continue
                except OSError:
                    continue

            # Binary / minified checks (only after fpath is defined)
            if skip_binary and is_binary_file(fpath):
                continue
            if skip_minified and is_minified(fpath):
                continue

            files.append(fpath.resolve())

    logger.info("File discovery complete", root=str(root), count=len(files))
    return files


def _compute_file_hash(path: Path) -> Tuple[Path, str, float]:
    """Compute SHA‑256 hash of a file (streaming) and return (path, hexdigest, mtime)."""
    sha256 = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        mtime = os.path.getmtime(path)
        return (path, sha256.hexdigest(), mtime)
    except Exception as e:
        logger.error("Failed to hash file", path=str(path), error=str(e))
        raise


def hash_files(
    file_paths: List[Path],
    max_workers: Optional[int] = None,
) -> List[Tuple[Path, str, float]]:
    """
    Compute SHA‑256 hashes for a list of file paths in parallel.
    Returns a list of (path, hash, mtime).
    """
    if max_workers is None:
        max_workers = DEFAULT_HASHING_WORKERS

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_path = {executor.submit(_compute_file_hash, p): p for p in file_paths}
        for future in concurrent.futures.as_completed(future_to_path):
            path = future_to_path[future]
            try:
                res = future.result()
                results.append(res)
            except Exception:
                logger.warning("Skipping file due to hash error", path=str(path))
    return results

# Add to src/sca/file_hasher.py

import magic

def is_binary_file(file_path: Path) -> bool:
    """Return True if the file is binary (not text)."""
    try:
        mime = magic.from_file(str(file_path), mime=True)
        return not mime.startswith("text/") and mime != "application/json"
    except Exception:
        return False

def is_minified(file_path: Path, max_avg_line_length: int = 200) -> bool:
    """Heuristic: return True if the average line length > threshold (likely minified)."""
    suffix = file_path.suffix.lower()
    if suffix not in {".js", ".css", ".min.js", ".min.css"}:
        return False
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            if not lines:
                return False
            total_len = sum(len(line) for line in lines)
            avg = total_len / len(lines)
            return avg > max_avg_line_length
    except Exception:
        return False
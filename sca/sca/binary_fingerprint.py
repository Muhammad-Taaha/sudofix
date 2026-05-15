"""
Binary file detection, string extraction, and pseudo-dependency fingerprinting.

Identifies ELF/PE/Mach‑O binaries, extracts printable strings, and matches
them against user‑supplied regex patterns to create pseudo‑dependencies.
"""

from __future__ import annotations

import dataclasses
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from sca.cache import get_cached_file, store_file_result, get_db_path
from sca.file_hasher import _compute_file_hash
from sca.utils import get_logger

logger = get_logger(__name__)

# Magic bytes for common executable formats
ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"
MACHO_MAGICS = (
    b"\xfe\xed\xfa\xce",  # 32-bit
    b"\xfe\xed\xfa\xcf",  # 64-bit
    b"\xce\xfa\xed\xfe",  # 32-bit little
    b"\xcf\xfa\xed\xfe",  # 64-bit little
)

# Minimum length for extracted strings
DEFAULT_MIN_STRING_LENGTH = 4


@dataclasses.dataclass
class PseudoDependency:
    """A dependency inferred from binary strings (name, version, file)."""
    name: str
    version: str
    file_path: str


def is_binary_file(file_path: Path) -> bool:
    """Return True if the file starts with ELF, PE, or Mach‑O magic bytes."""
    try:
        with open(file_path, "rb") as f:
            header = f.read(4)
    except (OSError, PermissionError):
        return False

    if header.startswith(ELF_MAGIC):
        return True
    if header.startswith(PE_MAGIC):
        return True
    if header.startswith(MACHO_MAGICS):
        return True
    return False


def extract_strings(file_path: Path, min_length: int = DEFAULT_MIN_STRING_LENGTH) -> Set[str]:
    """
    Extract all printable ASCII sequences >= min_length from a file.
    Reads the whole file at once – suitable for typical binaries.
    """
    printable_chars = re.compile(rb"[ -~]+")   # ASCII space to tilde
    results: Set[str] = set()

    try:
        with open(file_path, "rb") as f:
            data = f.read()
        for match in printable_chars.finditer(data):
            s = match.group().decode("ascii", errors="ignore")
            if len(s) >= min_length:
                results.add(s)
    except (OSError, PermissionError):
        logger.warning("Could not read file for string extraction", path=str(file_path))
    return results


class BinaryFingerprinter:
    """
    Given a set of {library_name: regex} patterns, scans binary files,
    extracts strings, and creates PseudoDependency objects.
    Results are cached per file hash.
    """

    def __init__(
        self,
        known_patterns: Dict[str, str],
        cache_dir: Optional[str] = None,
    ):
        self.known_patterns = known_patterns
        self.db_path = get_db_path(cache_dir)

    def fingerprint(self, file_path: Path) -> List[PseudoDependency]:
        """Return pseudo‑dependencies found in a file, using cache if possible."""
        file_hash = self._compute_hash(file_path)
        if file_hash:
            cached = get_cached_file(self.db_path, file_hash)
            if cached and cached.get("type") == "binary_fingerprint":
                return [PseudoDependency(**d) for d in cached["data"]]

        results = self._scan_file(file_path)

        if file_hash:
            store_file_result(
                self.db_path,
                file_hash,
                str(file_path),
                os.path.getmtime(file_path) if file_path.exists() else 0,
                {
                    "type": "binary_fingerprint",
                    "data": [dataclasses.asdict(r) for r in results],
                },
            )
        return results

    def _scan_file(self, file_path: Path) -> List[PseudoDependency]:
        """Actual scanning logic (called only on cache miss)."""
        if not is_binary_file(file_path):
            return []

        strings = extract_strings(file_path)
        findings: List[PseudoDependency] = []
        for s in strings:
            for lib_name, pattern in self.known_patterns.items():
                m = re.search(pattern, s)
                if m:
                    version = m.group(1) if m.lastindex and m.lastindex >= 1 else "unknown"
                    findings.append(
                        PseudoDependency(
                            name=lib_name,
                            version=version,
                            file_path=str(file_path),
                        )
                    )
                    # break so we don't match the same string twice for different libs
                    break
        return findings

    def _compute_hash(self, file_path: Path) -> Optional[str]:
        """Return SHA‑256 hash of a file, or None on failure."""
        try:
            _, file_hash, _ = _compute_file_hash(file_path)
            return file_hash
        except Exception:
            return None
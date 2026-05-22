"""Optimised license and vendored-code scanners using scancode CLI."""

from __future__ import annotations

import dataclasses
import os
import re
import tempfile
from pathlib import Path
from typing import List, Optional, Set

from sca.cache import get_cached_file, store_file_result, get_db_path
from sca.file_hasher import (
    discover_files,
    _compute_file_hash,
    is_binary_file,
    is_minified,
)
from sca.scancode_wrapper import run_scan
from sca.utils import get_logger

logger = get_logger(__name__)

# Common license file names (case-insensitive)
LICENSE_FILE_PATTERNS = [
    "license",
    "licence",
    "copying",
    "copyright",
    "notice",
    "authors",
    "patents",
]

# Quick copyright line regex (English, simple)
COPYRIGHT_RE = re.compile(
    r"Copyright\s*\(c\)\s*(?:[0-9]{4}[-–—, ]*)*[0-9]{4}\s+[A-Za-z]",
    re.IGNORECASE,
)


@dataclasses.dataclass
class LicenseFinding:
    file_path: str
    license_expression: str
    spdx_id: str
    confidence: float
    start_line: int
    end_line: int
    copyright_holders: List[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class VendoredMatch:
    file_path: str
    package_name: str
    version: Optional[str] = None
    license_expression: Optional[str] = None
    copyright_holders: List[str] = dataclasses.field(default_factory=list)


class LicenseScanner:
    """Scan only license‑relevant files using scancode CLI."""

    def __init__(self, cache_dir: Optional[str] = None, timeout: int = 120, quiet: bool = True):
        self.db_path = get_db_path(cache_dir)
        self.timeout = timeout
        self.quiet = quiet

    def scan_directory(self, project_root: str, file_paths: Optional[List[Path]] = None) -> List[LicenseFinding]:
        # Always find license files by pattern, not just when file_paths is None
        candidate_files = self._find_candidate_files(project_root)

        files_to_scan = []
        cached_findings = []
        for fp in candidate_files:
            file_hash = self._compute_hash(fp)
            if file_hash is None:
                files_to_scan.append(fp)
                continue
            cached = get_cached_file(self.db_path, file_hash)
            if cached and cached.get("type") == "license":
                cached_findings.append(LicenseFinding(**cached["data"]))
            else:
                files_to_scan.append(fp)

        if not files_to_scan:
            return cached_findings

        base_dir = Path(project_root).resolve()

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            output_file = tmp.name

        file_list = [str(f.relative_to(base_dir)) for f in files_to_scan]
        try:
            raw, parsed = run_scan(
                file_list=file_list,
                output_file=output_file,
                scan_type="license",
                quiet=self.quiet,
                timeout=self.timeout,
                processes=4,
                cwd=str(base_dir),
            )
        except Exception as e:
            logger.warning(f"License scan failed: {e}")
            return cached_findings

        new_findings = []
        if parsed:
            for file_info in parsed.get("files", []):
                rel_path = file_info["path"]
                abs_path = str(base_dir / rel_path)

                if not os.path.exists(abs_path):
                    continue

                # Get license info from file_info
                license_expr = file_info.get("detected_license_expression") or ""
                spdx_expr = file_info.get("detected_license_expression_spdx") or ""
                
                # Skip if no licenses detected
                if not license_expr:
                    continue

                # Extract confidence and line numbers from license_detections.matches
                detections = file_info.get("license_detections", [])
                confidence = 0.0
                start_line = 0
                end_line = 0
                
                if detections:
                    # Get the first match from the first detection's matches
                    for detection in detections:
                        matches = detection.get("matches", [])
                        if matches:
                            first_match = matches[0]
                            confidence = max(confidence, first_match.get("score", 0.0))
                            if start_line == 0:
                                start_line = first_match.get("start_line", 0)
                                end_line = first_match.get("end_line", 0)

                copyrights = file_info.get("copyrights", [])
                holders = [c.get("holder", "") for c in copyrights if "holder" in c]

                finding = LicenseFinding(
                    file_path=abs_path,
                    license_expression=license_expr,
                    spdx_id=spdx_expr,
                    confidence=confidence,
                    start_line=start_line,
                    end_line=end_line,
                    copyright_holders=holders,
                )
                new_findings.append(finding)

                file_hash = self._compute_hash(Path(abs_path))
                if file_hash:
                    store_file_result(
                        self.db_path,
                        file_hash,
                        abs_path,
                        os.path.getmtime(abs_path),
                        {"type": "license", "data": dataclasses.asdict(finding)},
                    )

        os.unlink(output_file)
        return cached_findings + new_findings

    def _find_candidate_files(self, root: str) -> List[Path]:
        all_files = discover_files(root, max_file_size_mb=1)
        candidates: Set[Path] = set()

        for f in all_files:
            name_lower = f.name.lower()
            for pattern in LICENSE_FILE_PATTERNS:
                if pattern in name_lower:
                    candidates.add(f)
                    break
            if f not in candidates and f.suffix in {
                ".py", ".js", ".java", ".c", ".cpp", ".go", ".ts", ".sh", ".rb", ".php"
            }:
                try:
                    with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                        for _ in range(50):
                            line = fh.readline()
                            if not line:
                                break
                            if COPYRIGHT_RE.search(line):
                                candidates.add(f)
                                break
                except Exception:
                    pass
        return list(candidates)

    def _compute_hash(self, file_path: Path) -> Optional[str]:
        try:
            _, file_hash, _ = _compute_file_hash(file_path)
            return file_hash
        except Exception:
            return None


class VendoredScanner:
    """Detect vendored packages using scancode package scan."""

    def __init__(self, cache_dir: Optional[str] = None, timeout: int = 120, quiet: bool = True):
        self.db_path = get_db_path(cache_dir)
        self.timeout = timeout
        self.quiet = quiet

    def scan_directory(self, project_root: str, file_paths: Optional[List[Path]] = None) -> List[VendoredMatch]:
        if file_paths is None:
            candidate_files = discover_files(
                project_root, max_file_size_mb=1, skip_binary=True, skip_minified=True
            )
        else:
            candidate_files = [p for p in file_paths if not is_binary_file(p) and not is_minified(p)]

        files_to_scan = []
        cached_matches = []
        for fp in candidate_files:
            file_hash = self._compute_hash(fp)
            if file_hash is None:
                files_to_scan.append(fp)
                continue
            cached = get_cached_file(self.db_path, file_hash)
            if cached and cached.get("type") == "vendored":
                cached_matches.append(VendoredMatch(**cached["data"]))
            else:
                files_to_scan.append(fp)

        if not files_to_scan:
            return cached_matches

        base_dir = Path(project_root).resolve()

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            output_file = tmp.name

        file_list = [str(f.relative_to(base_dir)) for f in files_to_scan]
        try:
            raw, parsed = run_scan(
                file_list=file_list,
                output_file=output_file,
                scan_type="package",
                quiet=self.quiet,
                timeout=self.timeout,
                processes=4,
                cwd=str(base_dir),
            )
        except Exception as e:
            logger.warning(f"Vendored scan failed: {e}")
            return cached_matches

        new_matches = []
        if parsed:
            for file_info in parsed.get("files", []):
                rel_path = file_info.get("path", "")
                abs_path = str(base_dir / rel_path) if rel_path else "unknown"
                for pkg in file_info.get("package_data", []):
                    match = VendoredMatch(
                        file_path=abs_path,
                        package_name=pkg.get("name", ""),
                        version=pkg.get("version"),
                        license_expression=pkg.get("license_expression"),
                        copyright_holders=[],
                    )
                    new_matches.append(match)
                    file_hash = self._compute_hash(Path(abs_path))
                    if file_hash:
                        store_file_result(
                            self.db_path,
                            file_hash,
                            abs_path,
                            os.path.getmtime(abs_path),
                            {"type": "vendored", "data": dataclasses.asdict(match)},
                        )

        os.unlink(output_file)
        return cached_matches + new_matches

    def _compute_hash(self, file_path: Path) -> Optional[str]:
        try:
            _, file_hash, _ = _compute_file_hash(file_path)
            return file_hash
        except Exception:
            return None
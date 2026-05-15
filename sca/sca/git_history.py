"""Scan git history for removed/modified files and run security/license scans on them."""

from __future__ import annotations

import dataclasses
import os
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple

from sca.file_hasher import _compute_file_hash, discover_files
from sca.cache import get_cached_file, store_file_result, get_db_path
from sca.scanners import LicenseScanner, VendoredScanner
from sca.rule_scanner import RuleScanner, HAS_AST_GREP
from sca.utils import get_logger

logger = get_logger(__name__)


@dataclasses.dataclass
class HistoryFinding:
    commit_hash: str
    file_path: str           # path relative to repo root at that commit
    file_sha256: str
    license_findings: List = dataclasses.field(default_factory=list)
    vendored_matches: List = dataclasses.field(default_factory=list)
    rule_findings: List = dataclasses.field(default_factory=list)


class GitHistoryScanner:
    """Scan git history for vulnerabilities/license changes in removed/modified files."""

    def __init__(
        self,
        repo_path: str,
        cache_dir: Optional[str] = None,
        max_commits: Optional[int] = None,
        since: Optional[str] = None,   # e.g. "2024-01-01"
    ):
        self.repo_path = Path(repo_path).resolve()
        self.db_path = get_db_path(cache_dir)
        self.max_commits = max_commits
        self.since = since
        self._license_scanner = LicenseScanner(cache_dir=cache_dir)
        self._vendored_scanner = VendoredScanner(cache_dir=cache_dir)
        self._rule_scanner = None
        if HAS_AST_GREP:
            try:
                self._rule_scanner = RuleScanner(cache_dir=cache_dir)
            except ImportError:
                pass

    def scan(self) -> List[HistoryFinding]:
        """Run the full history scan and return findings."""
        commits = self._get_relevant_commits()
        if not commits:
            logger.info("No commits to scan.")
            return []

        findings = []
        for commit_hash in commits:
            try:
                changed_files = self._get_changed_files(commit_hash)
                for file_path, file_hash, content in changed_files:
                    cached = self._check_cache(file_hash)
                    if cached:
                        findings.append(cached)
                        continue

                    # Write content to temp file for scanning
                    with tempfile.NamedTemporaryFile(
                        suffix=Path(file_path).suffix, delete=False, mode="w", encoding="utf-8"
                    ) as tmp:
                        tmp.write(content)
                        tmp_path = tmp.name

                    # Run scanners on this temp file
                    lic_findings = self._license_scanner.scan_directory(
                        str(Path(tmp_path).parent), file_paths=[Path(tmp_path)]
                    )
                    vend_matches = self._vendored_scanner.scan_directory(
                        str(Path(tmp_path).parent), file_paths=[Path(tmp_path)]
                    )
                    rule_findings = []
                    if self._rule_scanner:
                        rule_findings = self._rule_scanner.scan_files([Path(tmp_path)])

                    os.unlink(tmp_path)

                    finding = HistoryFinding(
                        commit_hash=commit_hash,
                        file_path=file_path,
                        file_sha256=file_hash,
                        license_findings=[dataclasses.asdict(f) for f in lic_findings],
                        vendored_matches=[dataclasses.asdict(m) for m in vend_matches],
                        rule_findings=[dataclasses.asdict(r) for r in rule_findings],
                    )
                    self._store_cache(file_hash, finding)
                    findings.append(finding)
            except Exception as e:
                logger.warning(f"Error scanning commit {commit_hash}: {e}")

        return findings

    def _get_relevant_commits(self) -> List[str]:
        """Get list of commit hashes that removed or modified files."""
        cmd = ["git", "log", "--diff-filter=DM", "--format=%H", "--no-merges"]
        if self.since:
            cmd += [f"--since={self.since}"]
        if self.max_commits:
            cmd += [f"-n", str(self.max_commits)]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(self.repo_path),
            check=True,
        )
        commits = result.stdout.strip().splitlines()
        logger.info(f"Found {len(commits)} relevant commits.")
        return commits

    def _get_changed_files(self, commit_hash: str) -> List[Tuple[str, str, str]]:
        """For a given commit, return list of (relative_path, sha256, content) for changed files."""
        # Get list of changed files (deleted/modified)
        files = subprocess.run(
            ["git", "diff-tree", "--no-commit-id", "--diff-filter=DM", "-r", "--name-only", commit_hash],
            capture_output=True,
            text=True,
            cwd=str(self.repo_path),
            check=True,
        ).stdout.strip().splitlines()

        results = []
        for fpath in files:
            if not fpath:
                continue
            # For deleted files, we need to look at the parent commit
            if subprocess.run(
                ["git", "cat-file", "-e", f"{commit_hash}:{fpath}"],
                capture_output=True,
                cwd=str(self.repo_path),
            ).returncode != 0:
                # File deleted; get content from parent commit
                content = self._get_file_content(f"{commit_hash}^", fpath)
            else:
                content = self._get_file_content(commit_hash, fpath)

            if content is not None:
                file_hash = _compute_file_hash_from_str(content)
                results.append((fpath, file_hash, content))
        return results

    def _get_file_content(self, treeish: str, file_path: str) -> Optional[str]:
        """Return file content at a given treeish (commit or parent)."""
        try:
            proc = subprocess.run(
                ["git", "show", f"{treeish}:{file_path}"],
                capture_output=True,
                text=True,
                cwd=str(self.repo_path),
                check=True,
            )
            return proc.stdout
        except subprocess.CalledProcessError:
            return None

    def _check_cache(self, file_hash: str) -> Optional[HistoryFinding]:
        cached = get_cached_file(self.db_path, file_hash)
        if cached and cached.get("type") == "history":
            return HistoryFinding(**cached["data"])
        return None

    def _store_cache(self, file_hash: str, finding: HistoryFinding):
        store_file_result(
            self.db_path,
            file_hash,
            finding.file_path,
            os.path.getmtime(self.repo_path / finding.file_path) if (self.repo_path / finding.file_path).exists() else 0,
            {"type": "history", "data": dataclasses.asdict(finding)},
        )


def _compute_file_hash_from_str(content: str) -> str:
    """Compute SHA‑256 hash of a string."""
    import hashlib
    sha256 = hashlib.sha256()
    sha256.update(content.encode("utf-8"))
    return sha256.hexdigest()
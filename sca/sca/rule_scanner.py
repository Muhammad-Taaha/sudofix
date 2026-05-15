"""Run ast-grep rules on source files, with caching."""

from __future__ import annotations

import dataclasses
import os
from pathlib import Path
from typing import Dict, List, Optional

try:
    from ast_grep_py import SgRoot
    HAS_AST_GREP = True
except ImportError:
    HAS_AST_GREP = False
    SgRoot = None

import yaml

from sca.cache import get_cached_file, store_file_result, get_db_path
from sca.file_hasher import _compute_file_hash
from sca.utils import get_logger

logger = get_logger(__name__)

# Extension -> language identifier for ast-grep
EXT_TO_LANG = {
    ".py": "Python",
    ".pyi": "Python",
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".java": "Java",
    ".go": "Go",
    ".c": "C",
    ".cpp": "Cpp",
    ".cc": "Cpp",
    ".cxx": "Cpp",
    ".h": "C",
    ".hpp": "Cpp",
    ".rs": "Rust",
    ".rb": "Ruby",
    ".php": "PHP",
    ".swift": "Swift",
    ".kt": "Kotlin",
    ".scala": "Scala",
}


@dataclasses.dataclass
class RuleFinding:
    file_path: str
    rule_id: str
    severity: str
    message: str
    line_start: int
    line_end: int
    code_snippet: str


class RuleScanner:
    """Run ast-grep rules on source files, using a local rule directory."""

    def __init__(self, rules_dir: Optional[str] = None, cache_dir: Optional[str] = None):
        if not HAS_AST_GREP:
            raise ImportError(
                "ast-grep-py is not installed. Install with `pip install ast-grep-py`"
            )
        self.db_path = get_db_path(cache_dir)
        self.rules_dir = Path(rules_dir) if rules_dir else Path(__file__).parent / "db" / "rules"

    def scan_files(self, file_paths: List[Path]) -> List[RuleFinding]:
        # 1. Separate cached from new
        files_to_scan: List[Path] = []
        cached_findings: List[RuleFinding] = []

        for fp in file_paths:
            file_hash = self._compute_hash(fp)
            if file_hash is None:
                files_to_scan.append(fp)
                continue
            cached = get_cached_file(self.db_path, file_hash)
            if cached and cached.get("type") == "rule":
                for item in cached["data"]:
                    cached_findings.append(RuleFinding(**item))
            else:
                files_to_scan.append(fp)

        if not files_to_scan:
            return cached_findings

        # 2. Load rules
        rules: List[Dict] = []
        for rule_file in self.rules_dir.glob("*.yml"):
            try:
                with open(rule_file, "r", encoding="utf-8") as f:
                    rule_dict = yaml.safe_load(f)
                if rule_dict:
                    rules.append(rule_dict)
            except Exception as e:
                logger.warning(f"Failed to load rule file {rule_file}: {e}")

        if not rules:
            logger.warning("No rules loaded from %s", self.rules_dir)
            return cached_findings

        # 3. Scan each file
        new_findings: List[RuleFinding] = []
        for fp in files_to_scan:
            lang = EXT_TO_LANG.get(fp.suffix.lower())
            if not lang:
                continue

            try:
                source = fp.read_text(encoding="utf-8", errors="ignore")
                sg_root = SgRoot(source, lang)
                root_node = sg_root.root()
            except Exception as e:
                logger.debug(f"Cannot parse {fp}: {e}")
                continue

            file_findings: List[RuleFinding] = []
            for rule_dict in rules:
                pattern = rule_dict.get("rule", {}).get("pattern", "")
                if not pattern:
                    continue

                try:
                    matches = root_node.find_all(pattern=pattern)
                except Exception as e:
                    logger.debug(f"Pattern failed on {fp}: {pattern} {e}")
                    continue

                for match in matches:
                    line_start = match.range().start.line + 1
                    line_end = match.range().end.line + 1
                    lines = source.splitlines()
                    snippet = (
                        "\n".join(lines[line_start - 1 : line_end])
                        if line_start <= len(lines)
                        else ""
                    )
                    finding = RuleFinding(
                        file_path=str(fp),
                        rule_id=rule_dict.get("id", "unknown"),
                        severity=rule_dict.get("severity", "medium"),
                        message=rule_dict.get("message", ""),
                        line_start=line_start,
                        line_end=line_end,
                        code_snippet=snippet,
                    )
                    file_findings.append(finding)

            if file_findings:
                new_findings.extend(file_findings)
                file_hash = self._compute_hash(fp)
                if file_hash:
                    store_file_result(
                        self.db_path,
                        file_hash,
                        str(fp),
                        os.path.getmtime(fp),
                        {
                            "type": "rule",
                            "data": [dataclasses.asdict(f) for f in file_findings],
                        },
                    )

        return cached_findings + new_findings

    def _compute_hash(self, file_path: Path) -> Optional[str]:
        try:
            _, file_hash, _ = _compute_file_hash(file_path)
            return file_hash
        except Exception:
            return None
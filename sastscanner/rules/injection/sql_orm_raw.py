import re
from typing import Any, Dict, List

from ...findings.finding import Finding
from ..base_rule import BaseRule


class SqlOrmRawRule(BaseRule):
    @property
    def name(self) -> str:
        return "ORM Raw SQL Execution"

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def cwe_id(self) -> str:
        return "CWE-89"

    REGEX_PATTERNS = {
        "python": r"\.(raw|execute)\s*\(\s*[^)]*\+",
        # Add other languages when needed: "java": r"\.createNativeQuery\([^)]*\+",
    }

    def check(self, node, context):
        lang = node.get("language", "").lower()
        if lang not in self.REGEX_PATTERNS:
            return []
        code = node.get("content", "")
        if re.search(self.REGEX_PATTERNS[lang], code):
            return [self._make_finding(node, lang)]
        return []

    def _make_finding(self, node, lang):
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            file_path=node.get("file_path", ""),
            line_start=node.get("start_line", 1),
            line_end=node.get("end_line", 1),
            message=f"ORM raw query with string concatenation in {lang.upper()}.",
            code_snippet="",
            cwe_id=self.cwe_id,
        )

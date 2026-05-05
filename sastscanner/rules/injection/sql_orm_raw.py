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

    def check(self, node: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        lang = node.get("language", "").lower()
        if lang != "python":
            return []

        code = node.get("content", "")
        # Only flag Django .raw() and SQLAlchemy .execute() with concatenation
        if re.search(r'\.raw\s*\(\s*["\'][^"\']*["\']\s*\+', code):
            return [self._make_finding(node)]
        if re.search(r'\.text\s*\(\s*["\'][^"\']*["\']\s*\+', code):
            return [self._make_finding(node)]
        return []

    def _make_finding(self, node):
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            file_path=node.get("file_path", ""),
            line_start=node.get("start_line", 1),
            line_end=node.get("end_line", 1),
            message="ORM raw query with string concatenation.",
            code_snippet="",
            cwe_id=self.cwe_id,
        )

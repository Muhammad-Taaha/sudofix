from typing import List, Dict, Any
import re
from ..base_rule import BaseRule
from ...findings.finding import Finding

class NoSqlMongoRule(BaseRule):
    @property
    def name(self) -> str:
        return "NoSQL Injection (MongoDB)"

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def cwe_id(self) -> str:
        return "CWE-943"

    def check(self, node: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        lang = node.get("language", "").lower()
        if lang not in ("javascript", "js"):
            return []

        code = node.get("content", "")
        if re.search(r'\$where\s*:\s*`[^`]*\${', code):
            return [self._make_finding(node)]
        return []

    def _make_finding(self, node):
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            file_path=node.get("file_path", ""),
            line_start=node.get("start_line", 1),
            line_end=node.get("end_line", 1),
            message="NoSQL injection via MongoDB $where operator with user input.",
            code_snippet="",
            cwe_id=self.cwe_id
        )
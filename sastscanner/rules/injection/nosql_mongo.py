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

    def check(self, chunk: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        lang = self._get_language(chunk)
        if not lang or lang not in ("javascript", "js"):
            return []

        code = chunk.get("content", "")
        # Look for $where operator with template string interpolation (${...})
        if re.search(r'\$where\s*:\s*`[^`]*\${', code):
            return [self._make_finding(chunk)]
        return []

    def _make_finding(self, chunk):
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            file_path=chunk.get("file_path", ""),
            line_start=chunk.get("start_line", 1),
            line_end=chunk.get("end_line", 1),
            message="NoSQL injection via MongoDB $where operator with user input.",
            code_snippet="",
            cwe_id=self.cwe_id
        )
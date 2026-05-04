import re
from typing import Any, Dict, List

from ...findings.finding import Finding
from ..base_rule import BaseRule


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
        # Accept both 'javascript' and 'js'
        if lang not in ("javascript", "js"):
            return []

        code = node.get("content", "")
        # Match $where with template literal containing ${...}
        # Also allow double quotes or single quotes
        if re.search(r'\$where\s*:\s*["\'`][^"\'`]*\${', code, re.DOTALL):
            return [
                Finding(
                    rule_name=self.name,
                    severity=self.severity,
                    file_path=node.get("file_path", ""),
                    line_start=node.get("start_line", 1),
                    line_end=node.get("end_line", 1),
                    message="NoSQL injection via $where operator with user input.",
                    code_snippet="",
                    cwe_id=self.cwe_id,
                )
            ]
        return []

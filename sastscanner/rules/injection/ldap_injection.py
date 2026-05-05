import re
from typing import Any, Dict, List

from ...findings.finding import Finding
from ..base_rule import BaseRule


class LdapInjectionRule(BaseRule):
    @property
    def name(self) -> str:
        return "LDAP Injection"

    @property
    def severity(self) -> str:
        return "MEDIUM"

    @property
    def cwe_id(self) -> str:
        return "CWE-90"

    def check(self, node: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        lang = node.get("language", "").lower()
        if lang != "python":
            return []

        code = node.get("content", "")
        # Flag only when search_s is called with a variable that is NOT escaped
        # Simple heuristic: if the filter argument is a variable that is not obviously escaped
        if re.search(r"search_s\s*\([^,]+,[^,]+,\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)", code):
            # Exclude if the variable is named 'safe_filter' or 'escaped_filter'
            if not re.search(
                r"search_s\([^,]+,[^,]+,\s*(safe_filter|escaped_filter)\s*\)", code
            ):
                return [self._make_finding(node)]
        return []

    def _make_finding(self, node):
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            file_path=node.get("file_path", ""),
            line_start=node.get("start_line", 1),
            line_end=node.get("end_line", 1),
            message="Potential LDAP injection with unsanitized filter.",
            code_snippet="",
            cwe_id=self.cwe_id,
        )

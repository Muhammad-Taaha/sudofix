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

    REGEX_PATTERNS = {
        "python": r"search_s\s*\(.*,\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)",
        "java": r"search\s*\(.*,\s*[a-zA-Z_]+",
        "php": r"ldap_search\s*\(.*,\s*\$",
    }

    def check(self, node, context):
        lang = node.get("language", "").lower()
        if lang not in self.REGEX_PATTERNS:
            return []
        code = node.get("content", "")
        if re.search(self.REGEX_PATTERNS[lang], code):
            return [
                Finding(
                    rule_name=self.name,
                    severity=self.severity,
                    file_path=node.get("file_path", ""),
                    line_start=node.get("start_line", 1),
                    line_end=node.get("end_line", 1),
                    message=f"Potential LDAP injection in {lang.upper()}.",
                    code_snippet="",
                    cwe_id=self.cwe_id,
                )
            ]
        return []

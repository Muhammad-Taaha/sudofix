from typing import List, Dict, Any
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import AssignNode

class CsrfDisabledRule(BaseRule):
    @property
    def name(self) -> str:
        return "Django CSRF Disabled"
    @property
    def severity(self) -> str:
        return "HIGH"
    @property
    def cwe_id(self) -> str:
        return "CWE-352"

    def check(self, chunk: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        lang = self._get_language(chunk)
        if lang != "python":
            return []
        nodes = chunk.get("nodes", [])
        for node in nodes:
            if isinstance(node, AssignNode):
                # Look for CSRF setting in code (simplistic)
                if "CSRF_USE_SESSIONS" in node.code and "False" in node.code:
                    return [self._create_finding(chunk, node)]
                if "CSRF_COOKIE_SECURE" in node.code and "False" in node.code:
                    return [self._create_finding(chunk, node)]
        return []

    def _create_finding(self, chunk, node):
        return Finding(
            self.name,
            self.severity,
            chunk.get("file_path", ""),
            node.start_line,
            node.end_line,
            "CSRF protection disabled in Django settings.",
            node.code,
            self.cwe_id,
        )
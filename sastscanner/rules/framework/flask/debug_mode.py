from typing import List, Dict, Any
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import AssignNode

class FlaskDebugModeRule(BaseRule):
    @property
    def name(self) -> str:
        return "Flask DEBUG=True in Production"
    @property
    def severity(self) -> str:
        return "HIGH"
    @property
    def cwe_id(self) -> str:
        return "CWE-489"

    def check(self, chunk, context):
        lang = self._get_language(chunk)
        if lang != "python":
            return []
        nodes = chunk.get("nodes", [])
        for node in nodes:
            if isinstance(node, AssignNode):
                if "debug=True" in node.code or "DEBUG=True" in node.code:
                    return [self._create_finding(chunk, node)]
        return []

    def _create_finding(self, chunk, node):
        return Finding(
            self.name,
            self.severity,
            chunk.get("file_path", ""),
            node.start_line,
            node.end_line,
            "Flask debug mode enabled – never use in production.",
            node.code,
            self.cwe_id,
        )
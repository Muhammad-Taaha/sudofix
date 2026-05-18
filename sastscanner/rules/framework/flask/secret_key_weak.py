from typing import List, Dict, Any
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import AssignNode

class FlaskSecretKeyWeakRule(BaseRule):
    @property
    def name(self) -> str:
        return "Flask Weak Secret Key"
    @property
    def severity(self) -> str:
        return "MEDIUM"
    @property
    def cwe_id(self) -> str:
        return "CWE-326"

    def check(self, chunk, context):
        lang = self._get_language(chunk)
        if lang != "python":
            return []
        nodes = chunk.get("nodes", [])
        for node in nodes:
            if isinstance(node, AssignNode):
                if "app.secret_key" in node.code:
                    # Check if the key is literal (hardcoded) or too short
                    if len(node.value) < 30 and "os.environ" not in node.value:
                        return [self._create_finding(chunk, node)]
        return []

    def _create_finding(self, chunk, node):
        return Finding(
            self.name,
            self.severity,
            chunk.get("file_path", ""),
            node.start_line,
            node.end_line,
            "Flask secret key is weak or hardcoded. Use a strong, environment‑sourced key.",
            node.code,
            self.cwe_id,
        )
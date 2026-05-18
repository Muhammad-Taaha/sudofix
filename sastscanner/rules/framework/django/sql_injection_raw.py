from typing import List, Dict, Any
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import CallNode
from ..literal_helpers import is_constant_literal

class DjangoRawSqlRule(BaseRule):
    @property
    def name(self) -> str:
        return "Django Raw SQL Injection"
    @property
    def severity(self) -> str:
        return "HIGH"
    @property
    def cwe_id(self) -> str:
        return "CWE-89"

    def check(self, chunk, context):
        lang = self._get_language(chunk)
        if lang != "python":
            return []
        nodes = chunk.get("nodes", [])
        findings = []
        for node in nodes:
            if not isinstance(node, CallNode):
                continue
            # Django raw SQL methods
            if node.callee in ("raw", "execute"):
                args = getattr(node, "arguments", [])
                if args and not is_constant_literal(args[0]):
                    findings.append(self._create_finding(chunk, node))
        return findings

    def _create_finding(self, chunk, node):
        return Finding(
            self.name,
            self.severity,
            chunk.get("file_path", ""),
            node.start_line,
            node.end_line,
            "Potential SQL injection via raw query with user input.",
            node.code,
            self.cwe_id,
        )
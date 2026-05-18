from typing import List, Dict, Any
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import CallNode

class PickleLoadRule(BaseRule):
    @property
    def name(self) -> str:
        return "Unsafe Deserialization (pickle)"
    @property
    def severity(self) -> str:
        return "HIGH"
    @property
    def cwe_id(self) -> str:
        return "CWE-502"

    def check(self, chunk, context):
        lang = self._get_language(chunk)
        if lang != "python":
            return []
        nodes = chunk.get("nodes", [])
        findings = []
        for node in nodes:
            if not isinstance(node, CallNode):
                continue
            if node.callee in ("pickle.loads", "pickle.load", "pickle.Unpickler"):
                findings.append(self._create_finding(chunk, node))
        return findings

    def _create_finding(self, chunk, node):
        return Finding(
            self.name,
            self.severity,
            chunk.get("file_path", ""),
            node.start_line,
            node.end_line,
            "Unsafe pickle deserialization – may lead to RCE.",
            node.code,
            self.cwe_id,
        )
from typing import List, Dict, Any
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import UnifiedNode
import re

class DangerousDefaultsRule(BaseRule):
    @property
    def name(self) -> str:
        return "Dangerous Mutable Default Argument"
    @property
    def severity(self) -> str:
        return "LOW"
    @property
    def cwe_id(self) -> str:
        return "CWE-665"

    def check(self, chunk: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        lang = self._get_language(chunk)
        if lang != "python":
            return []
        nodes = chunk.get("nodes", [])
        findings = []
        for node in nodes:
            if node.node_type != "function":
                continue
            code = node.code
            if re.search(r'=\s*\[\s*\]', code) or re.search(r'=\s*\{\s*\}', code) or re.search(r'=\s*set\s*\(', code):
                findings.append(self._create_finding(chunk, node))
        return findings

    def _create_finding(self, chunk, node):
        return Finding(
            self.name,
            self.severity,
            chunk.get("file_path", ""),
            node.start_line,
            node.end_line,
            f"Function '{node.name}' uses mutable default argument – can cause unexpected behavior.",
            node.code,
            self.cwe_id,
        )


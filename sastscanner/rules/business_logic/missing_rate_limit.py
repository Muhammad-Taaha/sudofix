from typing import List, Dict, Any
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import CallNode, AssignNode
import re

class MissingRateLimitRule(BaseRule):
    @property
    def name(self) -> str:
        return "Missing Rate Limiting"
    @property
    def severity(self) -> str:
        return "MEDIUM"
    @property
    def cwe_id(self) -> str:
        return "CWE-770"

    def check(self, chunk, context):
        lang = self._get_language(chunk)
        if lang != "python":
            return []
        nodes = chunk.get("nodes", [])
        # Look for Flask/DRF endpoints
        findings = []
        for node in nodes:
            if node.node_type == "function":
                # Check if the function has a decorator/annotation for rate limiting
                if "@rate_limit" not in node.code and "@throttle" not in node.code and "throttle_classes" not in node.code:
                    # Heuristic: function name with login, register, upload – may need rate limiting
                    if re.search(r'(login|register|upload)', node.name, re.IGNORECASE):
                        findings.append(self._create_finding(chunk, node))
        return findings

    def _create_finding(self, chunk, node):
        return Finding(
            self.name,
            self.severity,
            chunk.get("file_path", ""),
            node.start_line,
            node.end_line,
            f"Function '{node.name}' lacks rate limiting – could be abused.",
            node.code,
            self.cwe_id,
        )
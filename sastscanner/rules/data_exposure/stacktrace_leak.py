from typing import List, Dict, Any
import re
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import CallNode

class StacktraceLeakRule(BaseRule):
    @property
    def name(self) -> str:
        return "Stacktrace Information Leak"
    @property
    def severity(self) -> str:
        return "LOW"
    @property
    def cwe_id(self) -> str:
        return "CWE-209"

    def check(self, chunk, context):
        lang = self._get_language(chunk)
        if lang != "python":
            return []
        nodes = chunk.get("nodes", [])
        findings = []
        for node in nodes:
            if not isinstance(node, CallNode):
                continue
            # Catch exception handlers that print traceback
            if "traceback.print_exc" in node.callee or "traceback.format_exc" in node.callee:
                findings.append(self._create_finding(chunk, node))
        return findings

    def _create_finding(self, chunk, node):
        return Finding(
            self.name,
            self.severity,
            chunk.get("file_path", ""),
            node.start_line,
            node.end_line,
            "Stacktrace printed in production – may leak internal paths/structure.",
            node.code,
            self.cwe_id,
        )
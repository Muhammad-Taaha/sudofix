from typing import List, Dict, Any
import re
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import CallNode

class ReflectedXssRule(BaseRule):
    @property
    def name(self) -> str:
        return "Reflected XSS"
    @property
    def severity(self) -> str:
        return "HIGH"
    @property
    def cwe_id(self) -> str:
        return "CWE-79"

    # Sinks that return HTML/string directly from user input
    SINKS = {
        "python": {"render_template_string", "markupsafe.Markup", "jsonify", "make_response"},
    }

    def check(self, chunk, context):
        lang = self._get_language(chunk)
        if lang not in self.SINKS:
            return []
        nodes = chunk.get("nodes", [])
        findings = []
        for node in nodes:
            if not isinstance(node, CallNode):
                continue
            if node.callee in self.SINKS[lang]:
                # Heuristic: if any argument is not a constant literal, could be XSS
                if any(not self._is_literal(arg) for arg in node.arguments):
                    findings.append(self._create_finding(chunk, node))
        return findings

    def _is_literal(self, arg: str) -> bool:
        arg = arg.strip()
        return (arg.startswith('"') and arg.endswith('"')) or (arg.startswith("'") and arg.endswith("'"))

    def _create_finding(self, chunk, node):
        return Finding(
            self.name,
            self.severity,
            chunk.get("file_path", ""),
            node.start_line,
            node.end_line,
            f"Potential reflected XSS via {node.callee} with user input.",
            node.code,
            self.cwe_id,
        )
#this unsafe rendering is explitly for the python frameworks 
from typing import List, Dict, Any
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import CallNode

class UnsafeRenderingRule(BaseRule):
    @property
    def name(self) -> str:
        return "Unsafe Rendering / XSS via mark_safe"
    @property
    def severity(self) -> str:
        return "HIGH"
    @property
    def cwe_id(self) -> str:
        return "CWE-79"

    def check(self, chunk, context):
        lang = self._get_language(chunk)
        if lang != "python":
            return []
        nodes = chunk.get("nodes", [])
        findings = []
        for node in nodes:
            if not isinstance(node, CallNode):
                continue
            if node.callee == "mark_safe" or "|safe" in node.code:
                # Check if the argument is a variable (likely user input)
                args = getattr(node, "arguments", [])
                if args and not self._is_literal(args[0]):
                    findings.append(self._create_finding(chunk, node))
        return findings

    def _is_literal(self, arg):
        arg = arg.strip()
        return (arg.startswith('"') and arg.endswith('"')) or (arg.startswith("'") and arg.endswith("'"))

    def _create_finding(self, chunk, node):
        return Finding(
            self.name,
            self.severity,
            chunk.get("file_path", ""),
            node.start_line,
            node.end_line,
            "Unsafe rendering: mark_safe or |safe used on user input.",
            node.code,
            self.cwe_id,
        )
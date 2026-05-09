from typing import List, Dict, Any
import re
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import CallNode
from ..literal_helpers import is_constant_literal

class TemplateEngineRule(BaseRule):
    @property
    def name(self) -> str:
        return "Server‑Side Template Injection"

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def cwe_id(self) -> str:
        return "CWE-94"

    def check(self, chunk: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        lang = self._get_language(chunk)
        if not lang or lang != "python":
            return []

        nodes = chunk.get("nodes", [])
        findings = []

        for ast_node in nodes:
            if not isinstance(ast_node, CallNode):
                continue
            callee = getattr(ast_node, "callee", "")
            # Check for Jinja2 Template or Environment.from_string
            if "Template" in callee or "Environment.from_string" in callee:
                arguments = getattr(ast_node, "arguments", [])
                if arguments:
                    # First argument is template string
                    first_arg = arguments[0]
                    if not is_constant_literal(first_arg):
                        findings.append(self._make_finding(chunk, ast_node, callee))
                else:
                    # No arguments? Unlikely, but report anyway
                    findings.append(self._make_finding(chunk, ast_node, callee))

        # Fallback regex for safety
        if not findings:
            code = chunk.get("content", "")
            # Look for Template(variable) pattern
            if re.search(r'Template\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)', code):
                findings.append(self._make_finding(chunk, None, "Template with variable input (regex)"))

        return findings

    def _make_finding(self, chunk, ast_node, callee):
        line_start = ast_node.start_line if ast_node else chunk.get("start_line", 1)
        line_end = ast_node.end_line if ast_node else chunk.get("end_line", 1)
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            file_path=chunk.get("file_path", ""),
            line_start=line_start,
            line_end=line_end,
            message=f"Potential SSTI via `{callee}` with user-controlled template.",
            code_snippet=ast_node.code if ast_node else "",
            cwe_id=self.cwe_id
        )
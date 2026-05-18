from typing import List, Dict, Any
import re
from ..base_rule import BaseRule
from ...findings.finding import Finding

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

    def check(self, node: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        lang = node.get("language", "").lower()
        if lang != "python":
            return []

        ast_node = node.get("ast_node")
        if ast_node and getattr(ast_node, "node_type", "") == "call":
            callee = getattr(ast_node, "callee", "")
            if any(m in callee for m in ["Template", "Environment.from_string"]):
                args = getattr(ast_node, "arguments", [])
                if args:
                    first_arg = args[0].strip()
                    if first_arg and not (first_arg.startswith(('"', "'")) and first_arg.endswith(first_arg[0])):
                        return [self._make_finding(node, ast_node, callee)]
            return []

        code = node.get("content", "")
        if re.search(r'Template\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)', code):
            return [self._make_finding(node, None, "Template with variable input (regex)")]
        return []

    def _make_finding(self, node, ast_node, callee):
        line_start = ast_node.start_line if ast_node else node.get("start_line", 1)
        line_end = ast_node.end_line if ast_node else node.get("end_line", 1)
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            file_path=node.get("file_path", ""),
            line_start=line_start,
            line_end=line_end,
            message=f"Potential SSTI via `{callee}` with user-controlled template.",
            code_snippet="",
            cwe_id=self.cwe_id
        )
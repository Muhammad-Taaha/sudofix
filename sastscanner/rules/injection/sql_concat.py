import re
from typing import Any, Dict, List
from ...findings.finding import Finding
from ..base_rule import BaseRule
from parser.ast_nodes import CallNode
from ..literal_helpers import is_constant_literal


class SqlConcatRule(BaseRule):
    @property
    def name(self) -> str:
        return "SQL Injection via String Concatenation"

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def cwe_id(self) -> str:
        return "CWE-89"

    def check(self, node: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        lang = node.get("language", "").lower()
        ast_node = node.get("ast_node")

        # AST path for Python (most precise)
        if lang == "python" and isinstance(ast_node, CallNode):
            callee = ast_node.callee
            if any(sink in callee for sink in ["execute", "executemany"]):   # "raw" removed to avoid ORM overlap
                args = ast_node.arguments
                if not args:
                    return []
                # If the first argument is not a literal, assume concatenation/injection
                if not is_constant_literal(args[0]):
                    return [self._make_finding(node, ast_node, callee)]
            return []

        # Regex fallback for other languages (mirroring original logic)
        code = node.get("content", "")
        patterns = {
            "python": r'execute\s*\(\s*["\'][^"\']*["\']\s*\+',
            "javascript": r'\.(query|execute)\s*\(\s*["\'][^"\']*["\']\s*\+',
            "java": r'(executeQuery|executeUpdate|prepareStatement)\s*\(\s*["\'][^"\']*["\']\s*\+',
            "php": r"(query|exec|prepare)\s*\(\s*\$",
            "go": r'\.(Query|Exec)\s*\(\s*["\'][^"\']*["\']\s*\+',
        }
        pat = patterns.get(lang)
        if pat and re.search(pat, code):
            return [self._make_finding(node, None, f"SQL concatenation ({lang})")]
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
            message=f"Potential SQL injection via dynamic query in `{callee}`.",
            code_snippet=ast_node.code if ast_node else "",
            cwe_id=self.cwe_id,
        )
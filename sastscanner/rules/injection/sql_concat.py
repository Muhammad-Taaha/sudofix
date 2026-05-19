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

    def check(self, chunk: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        lang = self._get_language(chunk)
        if not lang:
            return []

        nodes = chunk.get("nodes", [])
        findings = []

        # AST-based detection (Python)
        if lang == "python":
            for ast_node in nodes:
                if not isinstance(ast_node, CallNode):
                    continue
                callee = ast_node.callee
                # Check for SQL execution methods
                if any(sink in callee for sink in ["execute", "executemany"]):
                    arguments = getattr(ast_node, "arguments", [])
                    if arguments:
                        # First argument is the SQL query
                        query_arg = arguments[0]
                        taint_vars = context.get("taint_vars")
                        if taint_vars:
                            is_tainted = False
                            for var in re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", str(query_arg)):
                                if taint_vars.is_tainted(var):
                                    is_tainted = True
                                    break
                            if is_tainted:
                                findings.append(self._make_finding(chunk, ast_node, callee))
                        elif not is_constant_literal(query_arg):
                            findings.append(self._make_finding(chunk, ast_node, callee))

        # Fallback regex for other languages
        if not findings:
            code = chunk.get("content", "")
            patterns = {
                "javascript": r'\.(query|execute)\s*\(\s*["\'][^"\']*["\']\s*\+',
                "java": r'(executeQuery|executeUpdate|prepareStatement)\s*\(\s*["\'][^"\']*["\']\s*\+',
                "php": r"(query|exec|prepare)\s*\(\s*\$",
                "go": r'\.(Query|Exec)\s*\(\s*["\'][^"\']*["\']\s*\+',
            }
            pat = patterns.get(lang)
            if pat and re.search(pat, code):
                findings.append(self._make_finding(chunk, None, f"SQL concatenation ({lang})"))

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
            message=f"Potential SQL injection via dynamic query in `{callee}`.",
            code_snippet=ast_node.code if ast_node else "",
            cwe_id=self.cwe_id,
        )
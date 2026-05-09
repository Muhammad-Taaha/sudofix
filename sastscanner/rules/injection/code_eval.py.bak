from typing import List, Dict, Any
import re
from ..base_rule import BaseRule
from ...findings.finding import Finding

class CodeEvalRule(BaseRule):
    @property
    def name(self) -> str:
        return "Dynamic Code Execution (eval/exec)"

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def cwe_id(self) -> str:
        return "CWE-95"

    def check(self, node: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        lang = node.get("language", "").lower()
        ast_node = node.get("ast_node")

        # AST path for Python
        if lang == "python" and ast_node and getattr(ast_node, "node_type", "") == "call":
            callee = getattr(ast_node, "callee", "")
            if callee in ["eval", "exec"]:
                args = getattr(ast_node, "arguments", [])
                tainted = any(
                    arg.strip() and not (arg.strip().startswith(('"', "'")) and arg.strip().endswith(arg.strip()[0]))
                    for arg in args
                )
                if tainted:
                    return [self._make_finding(node, ast_node, callee)]
            return []

        # Fallback regex
        code = node.get("content", "")
        patterns = {
            "python": r"\b(eval|exec)\s*\(",
            "javascript": r"\b(eval|Function)\s*\(",
            "java": r"ScriptEngine\.eval\s*\(",
            "php": r"\b(eval|assert)\s*\(",
            "ruby": r"\b(eval|instance_eval)\s*\(",
        }
        pat = patterns.get(lang)
        if pat and re.search(pat, code):
            return [self._make_finding(node, None, f"eval/exec ({lang})")]
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
            message=f"Dangerous dynamic code execution via `{callee}`.",
            code_snippet="",
            cwe_id=self.cwe_id
        )
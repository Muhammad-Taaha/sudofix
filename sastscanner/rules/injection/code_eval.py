import re
from typing import List, Dict, Any
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import CallNode

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

    def check(self, chunk: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        lang = self._get_language(chunk)
        if not lang:
            return []

        nodes = chunk.get("nodes", [])
        findings = []

        # AST-based detection (for languages where we have CallNode)
        for ast_node in nodes:
            if not isinstance(ast_node, CallNode):
                continue
            callee = getattr(ast_node, "callee", "")
            if lang == "python" and callee in ("eval", "exec"):
                # Check arguments – if any argument is not a constant literal
                arguments = getattr(ast_node, "arguments", [])
                for arg in arguments:
                    if not self._is_literal(arg):
                        findings.append(self._make_finding(chunk, ast_node, callee))
                        break
                else:
                    # if arguments list empty, still report
                    if not arguments:
                        findings.append(self._make_finding(chunk, ast_node, callee))

        # Fallback regex for languages without full AST support
        if not findings:
            code = chunk.get("content", "")
            patterns = {
                "python": r"\b(eval|exec)\s*\(",
                "javascript": r"\b(eval|Function)\s*\(",
                "java": r"ScriptEngine\.eval\s*\(",
                "php": r"\b(eval|assert)\s*\(",
                "ruby": r"\b(eval|instance_eval)\s*\(",
            }
            pat = patterns.get(lang)
            if pat and re.search(pat, code):
                findings.append(self._make_finding(chunk, None, f"eval/exec ({lang})"))

        return findings

    def _is_literal(self, arg: str) -> bool:
        """Simple check: if argument is a quoted string literal, treat as constant."""
        arg = arg.strip()
        if (arg.startswith('"') and arg.endswith('"')) or (arg.startswith("'") and arg.endswith("'")):
            return True
        return False

    def _make_finding(self, chunk, ast_node, callee):
        line_start = ast_node.start_line if ast_node else chunk.get("start_line", 1)
        line_end = ast_node.end_line if ast_node else chunk.get("end_line", 1)
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            file_path=chunk.get("file_path", ""),
            line_start=line_start,
            line_end=line_end,
            message=f"Dangerous dynamic code execution via `{callee}`.",
            code_snippet=ast_node.code if ast_node else "",
            cwe_id=self.cwe_id
        )
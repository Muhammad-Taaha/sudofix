import re
from typing import Any, Dict, List

from ...findings.finding import Finding
from ..base_rule import BaseRule


class CommandInjectionRule(BaseRule):
    @property
    def name(self) -> str:
        return "Command Injection"

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def cwe_id(self) -> str:
        return "CWE-78"

    def check(self, node: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        lang = node.get("language", "").lower()
        ast_node = node.get("ast_node")

        # Use AST for Python (if available)
        if (
            lang == "python"
            and ast_node
            and getattr(ast_node, "node_type", "") == "call"
        ):
            callee = getattr(ast_node, "callee", "")
            # Dangerous sinks
            if callee in ["os.system", "os.popen"]:
                # Check argument taint
                args = getattr(ast_node, "arguments", [])
                if args and not self._is_constant_string(args[0]):
                    return [self._make_finding(node, ast_node, callee)]
            elif "subprocess." in callee and any(
                f in callee
                for f in ["call", "Popen", "run", "check_call", "check_output"]
            ):
                # Check for shell=True
                args = getattr(ast_node, "arguments", [])
                if any("shell=True" in arg for arg in args):
                    # Also check command taint
                    if not self._is_constant_string(args[0] if args else ""):
                        return [self._make_finding(node, ast_node, callee)]
            return []

        # Fallback regex (for non‑Python or when AST missing)
        code = node.get("content", "")
        # Only catch dangerous patterns with variable arguments
        vulnerable_patterns = {
            "python": [
                r"os\.system\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)",
                r"os\.popen\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)",
                r"subprocess\.(call|Popen|run|check_call|check_output)\s*\([^)]*shell\s*=\s*True",
            ],
            "javascript": [
                r"child_process\.(exec|execSync)\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)"
            ],
            "java": [
                r"Runtime\.getRuntime\(\)\.exec\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)"
            ],
        }
        patterns = vulnerable_patterns.get(lang, [])
        for pat in patterns:
            if re.search(pat, code):
                return [self._make_finding(node, None, "command injection (regex)")]
        return []

    def _is_constant_string(self, arg: str) -> bool:
        """Return True if the argument is a literal string (quoted)."""
        stripped = arg.strip()
        return stripped.startswith(('"', "'")) and stripped.endswith(stripped[0])

    def _make_finding(self, node, ast_node, callee):
        line_start = ast_node.start_line if ast_node else node.get("start_line", 1)
        line_end = ast_node.end_line if ast_node else node.get("end_line", 1)
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            file_path=node.get("file_path", ""),
            line_start=line_start,
            line_end=line_end,
            message=f"Potential command injection via `{callee}` with user input.",
            code_snippet="",
            cwe_id=self.cwe_id,
        )

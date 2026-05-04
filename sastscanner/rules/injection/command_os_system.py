import re
from typing import Any, Dict, List

from ...findings.finding import Finding
from ..base_rule import BaseRule


class CommandInjectionRule(BaseRule):
    SINKS = {
        "python": {
            "modules": ["os", "subprocess"],
            "functions": [
                "system",
                "popen",
                "call",
                "check_call",
                "check_output",
                "run",
            ],
        },
        "c": {"functions": ["system", "popen"]},
        "cpp": {"functions": ["system", "popen"]},
        "java": {
            "classes": ["Runtime", "ProcessBuilder"],
            "functions": ["exec", "start"],
        },
        "javascript": {
            "modules": ["child_process"],
            "functions": ["exec", "execSync", "spawn", "fork"],
        },
        "go": {"functions": ["Command"]},
        "rust": {"functions": ["new", "output", "status"]},
        "php": {"functions": ["shell_exec", "exec", "system", "passthru", "popen"]},
        "ruby": {"functions": ["system", "exec", "`"]},
    }

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
        findings = []
        lang = node.get("language", "").lower()
        if lang not in self.SINKS:
            return findings

        ast_node = node.get("ast_node")
        # If no AST node, use regex fallback
        if not ast_node:
            return self._fallback_regex_check(node, lang)

        # If AST node exists but is not a call, use regex fallback as well
        if ast_node.node_type != "call":
            return self._fallback_regex_check(node, lang)

        # --- AST path (only reaches here if node_type == 'call') ---
        callee = getattr(ast_node, "callee", "")
        if "." in callee:
            module_part, func_part = callee.rsplit(".", 1)
        else:
            module_part, func_part = "", callee

        sink = self.SINKS[lang]
        if func_part in sink.get("functions", []):
            # Module/class context check
            if "modules" in sink and module_part and module_part not in sink["modules"]:
                return findings
            if "classes" in sink and module_part and module_part not in sink["classes"]:
                return findings

            if self._is_tainted(ast_node, node.get("content", "")):
                findings.append(self._create_finding(node, ast_node, callee))

        return findings

    def _is_tainted(self, ast_node, source_code: str) -> bool:
        args = getattr(ast_node, "arguments", [])
        for arg in args:
            stripped = arg.strip()
            if not (
                stripped.startswith(('"', "'", "`")) and stripped.endswith(stripped[0])
            ):
                return True
        return False

    def _create_finding(self, node: Dict[str, Any], ast_node, callee: str) -> Finding:
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            file_path=node.get("file_path", ""),
            line_start=ast_node.start_line,
            line_end=ast_node.end_line,
            message=f"Potential command injection via `{callee}`. Avoid using user input in system commands.",
            code_snippet=node.get("content", "").splitlines()[
                ast_node.start_line - node.get("start_line", 1)
            ],
            cwe_id=self.cwe_id,
        )

    def _fallback_regex_check(self, node: Dict[str, Any], lang: str) -> List[Finding]:
        code = node.get("content", "")
        patterns = {
            "python": r"(os\.system|os\.popen|subprocess\.(call|Popen|run))\s*\(",
            "javascript": r"child_process\.(exec|execSync)\s*\(",
            "java": r"Runtime\.getRuntime\(\)\.exec\s*\(",
            "php": r"(shell_exec|exec|system)\s*\(",
        }
        pat = patterns.get(lang)
        if pat and re.search(pat, code):
            return [
                Finding(
                    rule_name=self.name,
                    severity=self.severity,
                    file_path=node.get("file_path", ""),
                    line_start=node.get("start_line", 1),
                    line_end=node.get("end_line", 1),
                    message="Potential command injection (regex fallback).",
                    code_snippet="",
                    cwe_id=self.cwe_id,
                )
            ]
        return []

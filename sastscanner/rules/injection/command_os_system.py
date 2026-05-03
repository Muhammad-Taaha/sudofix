from typing import List, Dict, Any
from ..base_rule import BaseRule
from ...findings.finding import Finding

"""A file named command_injection.py most likely contains example code
   or a test script related to command injection —
   a type of security vulnerability where an attacker can
   execute arbitrary system commands through a program that unsafely processes user input.
"""


class CommandInjectionRule(BaseRule):
    # this sinks is actually working as a lookup table for the files
    # Language-specific sinks: module/class patterns and function names
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
            # For subprocess, we need to check if shell=True is used (optional)
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
        "go": {"functions": ["Command"]},  # exec.Command
        # std::process::Command
        "rust": {"functions": ["new", "output", "status"]},
        "php": {"functions": ["shell_exec", "exec", "system", "passthru", "popen"]},
        "ruby": {"functions": ["system", "exec", "`"]},
    }

    @property
    def name(self) -> str:

        return "Command Injection"

    @property
    def severity(self):

        return "High"

    @property
    def cwe_id(self) -> str:

        return "CWE-78"

    def check(self, node: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        """
        node: a dict representing a code entity, must contain at least:
              - 'ast_node' (the UnifiedNode from your parser)
              - 'language', 'file_path', 'start_line', 'end_line', 'content'
        """
        findings = []
        lang = node.get(
            "language", ""
        ).lower  # mkaing sure all th langhuages names are in lower cae just for keepinng the consistency
        if lang not in self.SINKS:

            return findings
        ast_node = node.get("ast_node")
        if not ast_node:
            return self._fallback_regex_check(node, lang)
            # For method calls like os.system, callee might be "os.system"
            # We split to get module and function
        if ast_node.node_type == "call":
            callee = getattr(ast_node, "callee", "")
            if "." in callee:
                module_part, func_part = callee.rsplit(".", 1)
            else:
                module_part, func_part = "", callee
            sink = self.SINKS[lang]
            # check if the function name matches
            if func_part in sink.get("function", []):
                """
                Modules/Classes: It groups these by their namespaces (like child_process in JS)
                to ensure the tool doesn't flag a random function that just happens to be named "run."

                """
                # Optionally check module/class context
                if (
                    "modules" in sink
                    and module_part
                    and module_part not in sink["modules"]
                ):
                    return findings
                if (
                    "classes" in sink
                    and module_part
                    and module_part not in sink["classes"]
                ):
                    return findings

                # Check if any argument is tainted (i.e., not a constant string)
                if self._is_tainted(ast_node, node.get("content", "")):
                    findings.append(self._create_finding(
                        node, ast_node, callee))

        return findings

    def _is_tainted(self, ast_node, source_code: str) -> bool:
        """
        Determine if any of the argument is a variable or a number not just a string

        """
        args = getattr(ast_node, "arguments", [])
        for arg in args:

            stripped = arg.strip()

            if not (
                stripped.startswith(
                    ('"', "'", "`")) and stripped.endswith(stripped[0])
            ):
                # Could also be a number or constant – but safe to treat as potential taint
                return True
        return False

    def _create_finding(self, node: Dict[str, Any], ast_node, callee: str) -> Finding:
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            file_path=node.get("file_path", ""),
            line_start=ast_node.start_line,
            line_end=ast_node.end_line,
            message=f"Potential command injection via `{
                callee}`. Avoid using user input in system commands.",
            code_snippet=node.get("content", "").splitlines()[
                ast_node.start_line - node.get("start_line", 1)
            ],
            cwe_id=self.cwe_id,
        )

    """
        If the AST isn't available for some reason, it calls _fallback_regex_check.
        This is basically a "dumb" search for keywords, acting as a backup.

    """

    def _fallback_regex_check(self, node: Dict[str, Any], lang: str) -> List[Finding]:
        """
        Fallback when AST is not available (not recommended).
        """
        # Quick pattern matching – far less accurate
        code = node.get("content", "")
        patterns = {
            "python": r"(os\.system|os\.popen|subprocess\.(call|Popen|run))\s*\(",
            "javascript": r"child_process\.(exec|execSync)\s*\(",
            "java": r"Runtime\.getRuntime\(\)\.exec\s*\(",
            "php": r"(shell_exec|exec|system)\s*\(",
        }
        import re

        pat = patterns.get(lang)
        if pat and re.search(pat, code):
            # fallback finding without precise line info
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

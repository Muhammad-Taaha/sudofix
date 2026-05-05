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

    SINKS = {
        "python": [
            "os.system",
            "os.popen",
            "subprocess.call",
            "subprocess.Popen",
            "subprocess.run",
            "subprocess.check_call",
            "subprocess.check_output",
        ],
        "javascript": ["child_process.exec", "child_process.execSync"],
        "java": ["Runtime.getRuntime().exec"],
        "go": ["exec.Command"],
        "php": ["shell_exec", "exec", "system", "passthru", "popen"],
        "ruby": ["system", "exec", "`"],
        "rust": ["std::process::Command"],
        "c": ["system", "popen"],
        "cpp": ["system", "popen"],
    }

    def check(self, node: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        lang = node.get("language", "").lower()
        ast_node = node.get("ast_node")

        # AST path only for Python (since only Python parser is upgraded)
        if (
            lang == "python"
            and ast_node
            and getattr(ast_node, "node_type", "") == "call"
        ):
            callee = getattr(ast_node, "callee", "")
            if callee in self.SINKS.get("python", []):
                args = getattr(ast_node, "arguments", [])
                tainted = any(
                    arg.strip()
                    and not (
                        arg.strip().startswith(('"', "'", "`"))
                        and arg.strip().endswith(arg.strip()[0])
                    )
                    for arg in args
                )
                if tainted:
                    return [self._make_finding(node, ast_node, callee)]
            return []

        # Fallback regex for all languages (including Python when AST fails)
        return self._regex_check(node, lang)

    def _regex_check(self, node, lang):
        code = node.get("content", "")
        patterns = {
            "python": r"(os\.system|os\.popen|subprocess\.(call|Popen|run|check_call|check_output))\s*\(",
            "javascript": r"child_process\.(exec|execSync)\s*\(",
            "java": r"Runtime\.getRuntime\(\)\.exec\s*\(",
            "go": r"exec\.Command\s*\(",
            "php": r"(shell_exec|exec|system|passthru|popen)\s*\(",
            "ruby": r"(system|exec|`)\s*\(",
            "rust": r"Command::new\s*\(",
            "c": r"(system|popen)\s*\(",
            "cpp": r"(system|popen)\s*\(",
        }
        pat = patterns.get(lang)
        if pat and re.search(pat, code):
            return [self._make_finding(node, None, f"command injection ({lang})")]
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
            message=f"Potential command injection via `{callee}` with user input.",
            code_snippet="",
            cwe_id=self.cwe_id,
        )

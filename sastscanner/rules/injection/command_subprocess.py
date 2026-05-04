import re
from typing import Any, Dict, List

from ...findings.finding import Finding
from ..base_rule import BaseRule


class CommandSubprocessRule(BaseRule):
    @property
    def name(self) -> str:
        return "Command Injection via Subprocess/Shell"

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def cwe_id(self) -> str:
        return "CWE-78"

    # Language-specific regex patterns for dangerous shell invocations
    REGEX_PATTERNS = {
        "python": r"subprocess\.(call|Popen|run|check_call|check_output)\s*\([^)]*shell\s*=\s*True",
        "javascript": r"child_process\.(exec|execSync)\s*\(",
        "java": r"Runtime\.getRuntime\(\)\.exec\s*\([^,)]*\+",
        "go": r"exec\.Command\([^)]*\+",
        "php": r"(shell_exec|exec|system|passthru|popen)\s*\(",
        "ruby": r"(system|exec|`)\s*\(",
        "rust": r"Command::new\([^)]*\+",
    }

    def check(self, node: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        lang = node.get("language", "").lower()
        if lang not in self.REGEX_PATTERNS:
            return []

        code = node.get("content", "")
        pattern = self.REGEX_PATTERNS[lang]
        if re.search(pattern, code):
            return [self._make_finding(node, lang)]
        return []

    def _make_finding(self, node, lang):
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            file_path=node.get("file_path", ""),
            line_start=node.get("start_line", 1),
            line_end=node.get("end_line", 1),
            message=f"Potential command injection (shell invocation) in {lang.upper()}.",
            code_snippet="",
            cwe_id=self.cwe_id,
        )

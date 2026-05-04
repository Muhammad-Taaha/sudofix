import re
from typing import Any, Dict, List

from ...findings.finding import Finding
from ..base_rule import BaseRule


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

    REGEX_PATTERNS = {
        "python": r"\b(eval|exec)\s*\(",
        "javascript": r"\b(eval|Function)\s*\(",
        "java": r"ScriptEngine\.eval\s*\(",
        "php": r"\b(eval|assert)\s*\(",
        "ruby": r"\b(eval|instance_eval)\s*\(",
    }

    def check(self, node, context):
        lang = node.get("language", "").lower()
        if lang not in self.REGEX_PATTERNS:
            return []
        code = node.get("content", "")
        if re.search(self.REGEX_PATTERNS[lang], code):
            return [self._make_finding(node, lang)]
        return []

    def _make_finding(self, node, lang):
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            file_path=node.get("file_path", ""),
            line_start=node.get("start_line", 1),
            line_end=node.get("end_line", 1),
            message=f"Dangerous dynamic code execution in {lang.upper()}.",
            code_snippet="",
            cwe_id=self.cwe_id,
        )

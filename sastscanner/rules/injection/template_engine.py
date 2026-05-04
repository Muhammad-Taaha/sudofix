import re
from typing import Any, Dict, List

from ...findings.finding import Finding
from ..base_rule import BaseRule


class TemplateEngineRule(BaseRule):
    @property
    def name(self) -> str:
        return "Server‑Side Template Injection"

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def cwe_id(self) -> str:
        return "CWE-94"

    REGEX_PATTERNS = {
        "python": r"Template\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)",
        "javascript": r"pug\.compile\s*\(\s*[a-zA-Z_]+",
        "php": r"new\s+Twig_Environment\([^,]+,\s*\['cache'=>false'?\]",
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
            message=f"Potential SSTI in {lang.upper()}.",
            code_snippet="",
            cwe_id=self.cwe_id,
        )

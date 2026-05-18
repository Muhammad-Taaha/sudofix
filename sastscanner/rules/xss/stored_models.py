from typing import List, Dict, Any
import re
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import AssignNode

class StoredXssRule(BaseRule):
    @property
    def name(self) -> str:
        return "Stored XSS (Unsanitized DB Input)"
    @property
    def severity(self) -> str:
        return "HIGH"
    @property
    def cwe_id(self) -> str:
        return "CWE-79"

    def check(self, chunk, context):
        lang = self._get_language(chunk)
        if lang != "python":
            return []
        nodes = chunk.get("nodes", [])
        findings = []
        for node in nodes:
            if not isinstance(node, AssignNode):
                continue
            # Check if the target is a Django model field (simplistic: contains .objects or .save)
            code = node.code
            if ".save()" in code or "objects.create" in code:
                # Check if the right‑hand side contains request data (GET/POST)
                if "request." in node.value or "request." in code:
                    findings.append(self._create_finding(chunk, node))
        return findings

    def _create_finding(self, chunk, node):
        return Finding(
            self.name,
            self.severity,
            chunk.get("file_path", ""),
            node.start_line,
            node.end_line,
            "User input saved to database without sanitization – potential stored XSS.",
            node.code,
            self.cwe_id,
        )
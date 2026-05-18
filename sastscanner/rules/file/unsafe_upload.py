from typing import List, Dict, Any
import re
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import CallNode

class UnsafeUploadRule(BaseRule):
    @property
    def name(self) -> str:
        return "Unsafe File Upload"

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def cwe_id(self) -> str:
        return "CWE-434"

    # Common upload‑handling method names
    UPLOAD_METHODS = {
        "python": ["save", "upload", "handle_uploaded_file"],
        "javascript": ["upload", "save", "store"],
        "java": ["transferTo", "save", "upload"],
        "go": ["SaveUploadedFile", "Upload"],
    }

    def check(self, chunk: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        lang = self._get_language(chunk)
        if lang not in self.UPLOAD_METHODS:
            return []

        nodes = chunk.get("nodes", [])
        findings = []
        for node in nodes:
            if not isinstance(node, CallNode):
                continue
            callee = node.callee.split('.')[-1]  # last part
            if callee not in self.UPLOAD_METHODS[lang]:
                continue

            # Check if there is any extension validation in the same chunk (simplistic)
            code = node.code
            if not re.search(r'\.(jpg|jpeg|png|gif|pdf|txt|docx|xlsx)', code, re.IGNORECASE):
                findings.append(self._create_finding(chunk, node, node.callee))

        return findings

    def _create_finding(self, chunk, node, callee):
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            file_path=chunk.get("file_path", ""),
            line_start=node.start_line,
            line_end=node.end_line,
            message=f"Potential unsafe file upload via `{callee}` without extension validation.",
            code_snippet=node.code,
            cwe_id=self.cwe_id,
        )
from typing import List, Dict, Any
import re
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import AssignNode
from ..literal_helpers import is_constant_literal

class HardcodedPasswordRule(BaseRule):
    @property
    def name(self) -> str:
        return "Hardcoded Password"
    @property
    def severity(self) -> str:
        return "CRITICAL"
    @property
    def cwe_id(self) -> str:
        return "CWE-259"

    def check(self, chunk: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        nodes = chunk.get("nodes", [])
        findings = []
        for node in nodes:
            if not isinstance(node, AssignNode):
                continue
            # Check targets (variable names) for password-like words
            for target in node.targets:
                if re.search(r'(?i)(password|passwd|pwd|secret)', target):
                    if is_constant_literal(node.value):
                        findings.append(self._create_finding(chunk, node, target))
                    break
        return findings

    def _create_finding(self, chunk, node, target):
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            file_path=chunk.get("file_path", ""),
            line_start=node.start_line,
            line_end=node.end_line,
            message=f"Hardcoded password in assignment to '{target}'",
            code_snippet=node.code,
            cwe_id=self.cwe_id,
        )
# sastscanner/rules/auth/hardcoded_password.py
from typing import List, Dict, Any
import re
import math
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import AssignNode, DictNode
from ..literal_helpers import is_constant_literal


class HardcodedPasswordRule(BaseRule):

    # 🔐 Expanded sensitive keywords
    SENSITIVE_PATTERN = re.compile(
        r'(?i)(password|passwd|pwd|secret|api[_-]?key|token|auth|credential)'
    )

    @property
    def name(self) -> str:
        return "Hardcoded Secret"

    @property
    def severity(self) -> str:
        return "CRITICAL"

    @property
    def cwe_id(self) -> str:
        return "CWE-259"

    # 🔢 Simple entropy calculator (Shannon entropy)
    def _calculate_entropy(self, value: str) -> float:
        if not value:
            return 0.0
        prob = [float(value.count(c)) / len(value) for c in set(value)]
        return -sum(p * math.log2(p) for p in prob)

    # 🔍 Check if string looks like a secret (high entropy)
    def _looks_like_secret(self, value: str) -> bool:
        if len(value) < 8:
            return False
        entropy = self._calculate_entropy(value)
        return entropy > 3.5  # threshold

    def check(self, chunk: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        nodes = chunk.get("nodes", [])
        findings = []

        for node in nodes:

            # =========================
            # 1. Assignment Detection
            # =========================
            if isinstance(node, AssignNode):
                target_match = None

                for target in node.targets:
                    if self.SENSITIVE_PATTERN.search(target):
                        target_match = target
                        break

                if target_match and is_constant_literal(node.value):
                    findings.append(
                        self._create_finding(chunk, node, target_match, "Hardcoded sensitive variable")
                    )
                    continue

                # 🔥 Entropy-based detection (even if variable name is not obvious)
                if is_constant_literal(node.value):
                    value = str(node.value).strip('"\'')
                    if self._looks_like_secret(value):
                        findings.append(
                            self._create_finding(chunk, node, "unknown", "High-entropy secret detected")
                        )

            # =========================
            # 2. Dictionary Detection
            # =========================
            if isinstance(node, DictNode):
                for key, value in zip(node.keys, node.values):
                    if isinstance(key, str) and self.SENSITIVE_PATTERN.search(key):
                        if is_constant_literal(value):
                            findings.append(
                                self._create_finding(chunk, node, key, "Hardcoded secret in dictionary")
                            )

        return findings

    def _create_finding(self, chunk, node, target, message_type):
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            file_path=chunk.get("file_path", ""),
            line_start=node.start_line,
            line_end=node.end_line,
            message=f"{message_type} in '{target}'",
            code_snippet=node.code,
            cwe_id=self.cwe_id,
        )
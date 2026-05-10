from typing import List, Dict, Any
import re
import math
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import AssignNode, DictNode
from ..literal_helpers import is_constant_literal


class HardcodedKeyRule(BaseRule):

    # 🔐 Expanded patterns
    KEY_PATTERN = re.compile(
        r'(?i)(api[_-]?key|secret|token|access[_-]?token|private[_-]?key|client[_-]?secret|auth)'
    )

    # 🔥 Known secret formats
    AWS_KEY = re.compile(r'AKIA[0-9A-Z]{16}')
    JWT_PATTERN = re.compile(r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+')
    PRIVATE_KEY_BLOCK = re.compile(r'-----BEGIN (RSA|EC|PRIVATE) KEY-----')

    @property
    def name(self) -> str:
        return "Hardcoded Cryptographic Key"

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def cwe_id(self) -> str:
        return "CWE-321"

    # 🔢 Entropy calculation
    def _entropy(self, s: str) -> float:
        if not s:
            return 0
        prob = [s.count(c) / len(s) for c in set(s)]
        return -sum(p * math.log2(p) for p in prob)

    def _is_high_entropy(self, s: str) -> bool:
        return len(s) > 8 and self._entropy(s) > 3.5

    def check(self, chunk: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        nodes = chunk.get("nodes", [])
        findings = []

        for node in nodes:

            # =========================
            # 1. Assignment detection
            # =========================
            if isinstance(node, AssignNode):

                for target in node.targets:

                    if is_constant_literal(node.value):
                        value = str(node.value).strip('"\'')
                        
                        # ✅ Keyword-based detection
                        if self.KEY_PATTERN.search(target):
                            findings.append(
                                self._create_finding(chunk, node, target, "Hardcoded key")
                            )
                            continue

                        # 🔥 Known patterns
                        if (self.AWS_KEY.search(value) or
                            self.JWT_PATTERN.search(value) or
                            self.PRIVATE_KEY_BLOCK.search(value)):
                            findings.append(
                                self._create_finding(chunk, node, target, "Known secret pattern")
                            )
                            continue

                        # ⚡ Entropy-based detection
                        if self._is_high_entropy(value):
                            findings.append(
                                self._create_finding(chunk, node, target, "High entropy secret")
                            )

            # =========================
            # 2. Dictionary detection
            # =========================
            if isinstance(node, DictNode):
                for key, value in zip(node.keys, node.values):
                    if isinstance(key, str) and self.KEY_PATTERN.search(key):
                        if is_constant_literal(value):
                            findings.append(
                                self._create_finding(chunk, node, key, "Hardcoded key in dict")
                            )

        return findings

    def _create_finding(self, chunk, node, target, msg):
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            file_path=chunk.get("file_path", ""),
            line_start=node.start_line,
            line_end=node.end_line,
            message=f"{msg} in '{target}'",
            code_snippet=node.code,
            cwe_id=self.cwe_id,
        )
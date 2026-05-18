from typing import List, Dict, Any
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import CallNode
from ..literal_helpers import is_constant_literal

class SpringJpaSqlInjectionRule(BaseRule):
    @property
    def name(self) -> str:
        return "Spring JPA SQL Injection"
    @property
    def severity(self) -> str:
        return "HIGH"
    @property
    def cwe_id(self) -> str:
        return "CWE-89"

    def check(self, chunk, context):
        lang = self._get_language(chunk)
        if lang != "java":
            return []
        nodes = chunk.get("nodes", [])
        findings = []
        for node in nodes:
            if not isinstance(node, CallNode):
                continue
            # JPA query methods (simplified)
            callee = node.callee
            if "createQuery" in callee or "createNativeQuery" in callee:
                args = getattr(node, "arguments", [])
                if args and not is_constant_literal(args[0]):
                    # Also check if using positional parameters (?) – if not, likely + concatenation
                    query_arg = args[0]
                    if "?" not in query_arg and ":" not in query_arg:
                        findings.append(self._create_finding(chunk, node))
        return findings

    def _create_finding(self, chunk, node):
        return Finding(
            self.name,
            self.severity,
            chunk.get("file_path", ""),
            node.start_line,
            node.end_line,
            "Potential SQL injection via JPQL/Native query with string concatenation.",
            node.code,
            self.cwe_id,
        )
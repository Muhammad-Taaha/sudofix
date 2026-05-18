from typing import List, Dict, Any
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import AssignNode, CallNode

class DomInnerHtmlRule(BaseRule):
    @property
    def name(self) -> str:
        return "DOM XSS via innerHTML"
    @property
    def severity(self) -> str:
        return "HIGH"
    @property
    def cwe_id(self) -> str:
        return "CWE-79"

    def check(self, chunk: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        lang = self._get_language(chunk)
        if lang not in ("javascript", "js"):
            return []
        nodes = chunk.get("nodes", [])
        findings = []
        for node in nodes:
            if isinstance(node, AssignNode):
                for target in node.targets:
                    if ".innerHTML" in target:
                        findings.append(self._create_finding(chunk, node))
                        break
            elif isinstance(node, CallNode) and "innerHTML" in node.callee:
                findings.append(self._create_finding(chunk, node))
        return findings

    def _create_finding(self, chunk, node):
        return Finding(
            self.name,
            self.severity,
            chunk.get("file_path", ""),
            node.start_line,
            node.end_line,
            "Potential DOM XSS: assigning user input to innerHTML.",
            node.code,
            self.cwe_id,
        )
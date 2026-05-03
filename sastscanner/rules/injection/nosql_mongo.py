from typing import List, Dict, Any
from ..base_rule import BaseRule
from ...findings.finding import Finding


class NoSqlMongoRule(BaseRule):
    """
    Detects NoSQL injection in MongoDB (JavaScript injection in $where, etc.).
    """

    SINKS = {
        "javascript": ["$where", "where"],
        "python": ["$where", "where"],
        "java": ["$where", "where"],
        "go": ["$where", "Where"],
    }

    @property
    def name(self) -> str:
        return "NoSQL Injection (MongoDB)"

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def cwe_id(self) -> str:
        return "CWE-943"

    def check(self, node: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        findings = []
        lang = node.get("language", "").lower()
        if lang not in self.SINKS:
            return findings

        ast_node = node.get("ast_node")
        if not ast_node or ast_node.node_type != "call":
            return findings

        # Look for MongoDB methods (e.g., collection.find({$where: ...}))
        code = node.get("content", "")
        import re

        for sink in self.SINKS[lang]:
            pattern = rf'{sink}\s*:\s*["\']?(?!\s*["\'])\S+'
            if re.search(pattern, code):
                findings.append(
                    Finding(
                        rule_name=self.name,
                        severity=self.severity,
                        file_path=node.get("file_path", ""),
                        line_start=node.get("start_line", 1),
                        line_end=node.get("end_line", 1),
                        message=f"Potential NoSQL injection via `{
                            sink}` operator with user input. Avoid dynamic JavaScript in queries.",
                        code_snippet=node.get("content", "").splitlines()[0],
                        cwe_id=self.cwe_id,
                    )
                )
                break
        return findings

from typing import List, Dict, Any
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import CallNode

class RaceConditionRule(BaseRule):
    @property
    def name(self) -> str:
        return "Potential Race Condition"
    @property
    def severity(self) -> str:
        return "MEDIUM"
    @property
    def cwe_id(self) -> str:
        return "CWE-362"

    def check(self, chunk, context):
        lang = self._get_language(chunk)
        if lang != "python":
            return []
        nodes = chunk.get("nodes", [])
        findings = []
        for node in nodes:
            if not isinstance(node, CallNode):
                continue
            # Detect file operations that may be unsafe without locking
            if node.callee in ("open", "os.remove", "os.rename"):
                # Check if the operation is inside a locked context (simple heuristic)
                code = node.code.lower()
                if "lock" not in code and "mutex" not in code and "atomic" not in code:
                    findings.append(self._create_finding(chunk, node))
        return findings

    def _create_finding(self, chunk, node):
        return Finding(
            self.name,
            self.severity,
            chunk.get("file_path", ""),
            node.start_line,
            node.end_line,
            "File operation without synchronization – possible race condition.",
            node.code,
            self.cwe_id,
        )
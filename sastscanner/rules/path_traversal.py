from typing import List, Dict, Any
import re
from .base_rule import BaseRule
from ..findings.finding import Finding
from parser.ast_nodes import CallNode

class PathTraversalRule(BaseRule):
    @property
    def name(self) -> str:
        return "Path Traversal"

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def cwe_id(self) -> str:
        return "CWE-22"

    def check(self, chunk: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        findings = []
        nodes = chunk.get("nodes", [])
        
        for ast_node in nodes:
            if not isinstance(ast_node, CallNode):
                continue
            
            callee = getattr(ast_node, "callee", "")
            if "open" in callee or "readFile" in callee or "FileInputStream" in callee:
                # Basic check for path traversal patterns in arguments
                arguments = getattr(ast_node, "arguments", [])
                for arg in arguments:
                    if "../" in str(arg) or "..\\" in str(arg):
                        findings.append(Finding(
                            rule_name=self.name,
                            severity=self.severity,
                            file_path=chunk.get("file_path", ""),
                            line_start=ast_node.start_line,
                            line_end=ast_node.end_line,
                            message=f"Potential Path Traversal detected in {callee}",
                            code_snippet=ast_node.code,
                            cwe_id=self.cwe_id
                        ))
        return findings

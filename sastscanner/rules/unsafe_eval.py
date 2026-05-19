from typing import List, Dict, Any
from .base_rule import BaseRule
from ..findings.finding import Finding
from parser.ast_nodes import CallNode

class UnsafeEvalRule(BaseRule):
    @property
    def name(self) -> str:
        return "Unsafe Eval Execution"

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def cwe_id(self) -> str:
        return "CWE-94"

    def check(self, chunk: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        findings = []
        nodes = chunk.get("nodes", [])
        
        for ast_node in nodes:
            if not isinstance(ast_node, CallNode):
                continue
            
            callee = getattr(ast_node, "callee", "")
            if callee in ["eval", "exec", "setTimeout", "setInterval", "Function"]:
                arguments = getattr(ast_node, "arguments", [])
                for arg in arguments:
                    # Check if the argument is likely a variable and not just a string literal
                    arg_str = str(arg).strip()
                    if not (arg_str.startswith('"') and arg_str.endswith('"')) and not (arg_str.startswith("'") and arg_str.endswith("'")):
                        findings.append(Finding(
                            rule_name=self.name,
                            severity=self.severity,
                            file_path=chunk.get("file_path", ""),
                            line_start=ast_node.start_line,
                            line_end=ast_node.end_line,
                            message=f"Unsafe use of {callee}() with dynamic arguments.",
                            code_snippet=ast_node.code,
                            cwe_id=self.cwe_id
                        ))
                        break
        return findings

from typing import List, Dict, Any
from ..base_rule import BaseRule
from ...findings.finding import Finding


class CodeEvalRule(BaseRule):
    """
    Detects dangerous dynamic code execution across languages.
    """

    SINKS = {
        "python": ["eval", "exec", "__import__", "compile"],
        "javascript": ["eval", "Function", "setTimeout", "setInterval"],
        "ruby": ["eval", "instance_eval", "class_eval"],
        "php": ["eval", "assert", "create_function"],
        "java": ["ScriptEngine.eval", "Method.invoke"],
    }

    @property
    def name(self) -> str:
        return "Dynamic Code Execution (eval/exec)"

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def cwe_id(self) -> str:
        return "CWE-95"

    def check(self, node: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        findings = []
        lang = node.get("language", "").lower()
        if lang not in self.SINKS:
            return findings

        ast_node = node.get("ast_node")
        if not ast_node or ast_node.node_type != "call":
            return findings

        callee = getattr(ast_node, "callee", "")
        if not any(sink in callee for sink in self.SINKS[lang]):
            return findings

        # Check if argument is tainted (not a constant string)
        args = getattr(ast_node, "arguments", [])
        tainted = False
        for arg in args:
            stripped = arg.strip()
            if stripped and not (
                stripped.startswith(
                    ('"', "'")) and stripped.endswith(stripped[0])
            ):
                tainted = True
                break

        if tainted:
            findings.append(
                Finding(
                    rule_name=self.name,
                    severity=self.severity,
                    file_path=node.get("file_path", ""),
                    line_start=ast_node.start_line,
                    line_end=ast_node.end_line,
                    message=f"Dangerous dynamic code execution via `{
                        callee}` with variable input. Avoid eval-like functions.",
                    code_snippet=node.get("content", "").splitlines()[
                        ast_node.start_line - node.get("start_line", 1)
                    ],
                    cwe_id=self.cwe_id,
                )
            )
        return findings

from typing import List, Dict, Any
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import CallNode, StrNode, NumNode, ListNode, NameNode


class CommandInjectionRule(BaseRule):
    @property
    def name(self) -> str:
        return "Command Injection"

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def cwe_id(self) -> str:
        return "CWE-78"

    SINKS = {
        "python": [
            "os.system", "os.popen",
            "subprocess.call", "subprocess.Popen", "subprocess.run",
            "subprocess.check_call", "subprocess.check_output"
        ],
        "javascript": ["child_process.exec", "child_process.execSync"],
        "java": ["Runtime.getRuntime().exec"],
        "go": ["exec.Command"],
        "php": ["shell_exec", "exec", "system", "passthru", "popen"],
        "ruby": ["system", "exec", "`"],
        "rust": ["Command::new"],
        "c": ["system", "popen"],
        "cpp": ["system", "popen"],
    }

    def check(self, node: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        lang = node.get("language", "").lower()
        if lang not in self.SINKS:
            return []

        ast_node = node.get("ast_node")
        if not isinstance(ast_node, CallNode):
            return []

        if ast_node.callee not in self.SINKS[lang]:
            return []

        # Examine all arguments; if any is not a safe literal, report a finding
        for arg in ast_node.arguments:
            if not self._is_safe_literal(arg):
                return [self._create_finding(node, ast_node, ast_node.callee)]

        return []

    def _is_safe_literal(self, arg_node) -> bool:
        """Recursively check if an AST node represents a constant literal."""
        # String literal
        if isinstance(arg_node, StrNode):
            # A plain string literal is safe (no user input concatenated)
            return True

        # Numeric literal
        if isinstance(arg_node, NumNode):
            return True

        # List literal: safe only if all elements are safe literals
        if isinstance(arg_node, ListNode):
            return all(self._is_safe_literal(elem) for elem in arg_node.elements)

        # Any other node (variable, binary operation, call, etc.) is considered unsafe
        return False

    def _create_finding(self, node: Dict, ast_node: CallNode, callee: str) -> Finding:
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            file_path=node.get("file_path", ""),
            line_start=ast_node.start_line,
            line_end=ast_node.end_line,
            message=f"Potential command injection via `{
                callee}` with user input.",
            code_snippet=ast_node.code,
            cwe_id=self.cwe_id
        )

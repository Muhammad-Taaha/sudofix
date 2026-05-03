import re
from typing import List, Dict, Any
from ..base_rule import BaseRule
from ...findings.finding import Finding


class SqlConcatRule(BaseRule):
    """
    Detects SQL query construction via string concatenation or formatting.
    Supports multiple languages using the unified AST.
    """

    # Language-specific sink patterns: function names that execute SQL
    SINKS = {
        "python": ["execute", "executemany", "raw", "cursor.execute"],
        "javascript": ["query", "execute", "run"],
        "java": [
            "executeQuery",
            "executeUpdate",
            "prepareStatement",
            "createStatement",
        ],
        "go": ["Query", "Exec", "QueryRow"],
        "php": ["query", "exec", "prepare"],
        "ruby": ["execute", "query"],
    }

    @property
    def name(self) -> str:
        return "SQL Injection via String Concatenation"

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def cwe_id(self) -> str:
        return "CWE-89"

    def check(self, node: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        findings = []
        lang = node.get("language", "").lower()
        if lang not in self.SINKS:
            return findings

        ast_node = node.get("ast_node")
        if not ast_node or ast_node.node_type != "call":
            return findings

        callee = getattr(ast_node, "callee", "")
        # Check if the function name is a known SQL execution method
        if not any(sink in callee for sink in self.SINKS[lang]):
            return findings

        # Now check if any argument contains string concatenation or formatting
        args = getattr(ast_node, "arguments", [])
        sql_arg = args[0] if args else ""
        if not sql_arg:
            return findings

        # Patterns indicating dynamic SQL: +, %, .format, f-string, etc.
        dynamic_patterns = [
            r"\+",  # concatenation
            r"%",  # old formatting
            r"\.format\(",  # .format()
            r'f"',  # f-string
            r"f'",  # f-string
        ]
        is_dynamic = any(re.search(p, sql_arg) for p in dynamic_patterns)

        if is_dynamic:
            findings.append(
                Finding(
                    rule_name=self.name,
                    severity=self.severity,
                    file_path=node.get("file_path", ""),
                    line_start=ast_node.start_line,
                    line_end=ast_node.end_line,
                    message=f"Potential SQL injection via dynamic SQL query construction in `{
                        callee}`. Use parameterized queries.",
                    code_snippet=node.get("content", "").splitlines()[
                        ast_node.start_line - node.get("start_line", 1)
                    ],
                    cwe_id=self.cwe_id,
                )
            )
        return findings

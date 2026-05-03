from typing import List, Dict, Any
from ..base_rule import BaseRule
from ...findings.finding import Finding


class SqlOrmRawRule(BaseRule):
    """
    Detects raw SQL execution in ORMs across languages.
    """

    SINKS = {
        "python": {
            "django": ["raw", "execute"],
            "sqlalchemy": ["text", "execute"],
            "peewee": ["raw"],
        },
        "java": {
            "jpa": ["createNativeQuery", "createQuery"],
            "hibernate": ["createSQLQuery"],
        },
        "csharp": ["ExecuteSqlRaw", "FromSqlRaw"],
        "go": ["Raw", "Exec"],
        "php": ["query", "exec"],
    }

    @property
    def name(self) -> str:
        return "ORM Raw SQL Execution"

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
        # Check if callee matches any ORM raw method
        matched = False
        for framework, methods in self.SINKS[lang].items():
            if any(m in callee for m in methods):
                matched = True
                break

        if not matched:
            return findings

        # Check if any argument suggests concatenation/variable (simplified)
        args = getattr(ast_node, "arguments", [])
        dangerous = False
        for arg in args:
            if "+" in arg or "%" in arg or ".format(" in arg:
                dangerous = True
                break

        if dangerous:
            findings.append(
                Finding(
                    rule_name=self.name,
                    severity=self.severity,
                    file_path=node.get("file_path", ""),
                    line_start=ast_node.start_line,
                    line_end=ast_node.end_line,
                    message=f"Raw SQL execution with dynamic query construction in `{
                        callee}`. Use parameterized queries.",
                    code_snippet=node.get("content", "").splitlines()[
                        ast_node.start_line - node.get("start_line", 1)
                    ],
                    cwe_id=self.cwe_id,
                )
            )
        return findings

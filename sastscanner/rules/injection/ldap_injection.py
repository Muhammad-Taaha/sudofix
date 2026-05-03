from typing import List, Dict, Any
from ..base_rule import BaseRule
from ...findings.finding import Finding


class LdapInjectionRule(BaseRule):
    """
    Detects LDAP injection via unsanitized user input in search filters.
    """

    SINKS = {
        "python": ["search", "search_s", "search_ext", "ldapsearch"],
        "java": ["search", "LdapContext.search"],
        "php": ["ldap_search", "ldap_list", "ldap_read"],
        "go": ["Search", "SimpleSearch"],
        "javascript": ["search", "ldap.search"],
    }

    @property
    def name(self) -> str:
        return "LDAP Injection"

    @property
    def severity(self) -> str:
        return "MEDIUM"

    @property
    def cwe_id(self) -> str:
        return "CWE-90"

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

        # Check if any argument contains variable (tainted)
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
                    message=f"Potential LDAP injection via `{
                        callee}` with variable filter. Use escaping or parameterized queries.",
                    code_snippet=node.get("content", "").splitlines()[
                        ast_node.start_line - node.get("start_line", 1)
                    ],
                    cwe_id=self.cwe_id,
                )
            )
        return findings

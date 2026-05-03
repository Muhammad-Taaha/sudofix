from typing import List, Dict, Any
from ..base_rule import BaseRule
from ...findings.finding import Finding


class TemplateEngineRule(BaseRule):
    """
    Detects unsafe template rendering (e.g., Jinja2, Twig, ERB) with user input.
    """

    SINKS = {
        "python": {
            "jinja2": ["Template", "Environment.from_string", "render"],
            "mako": ["Template", "render"],
        },
        "php": {"twig": ["createTemplate", "render"]},
        "ruby": {"erb": ["ERB.new", "result"]},
        "javascript": {"pug": ["compile", "render"]},
    }

    @property
    def name(self) -> str:
        return "Server‑Side Template Injection"

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def cwe_id(self) -> str:
        return "CWE-94"

    def check(self, node: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        findings = []
        lang = node.get("language", "").lower()
        if lang not in self.SINKS:
            return findings

        ast_node = node.get("ast_node")
        if not ast_node or ast_node.node_type != "call":
            return findings

        callee = getattr(ast_node, "callee", "")
        for engine, methods in self.SINKS[lang].items():
            if any(m in callee for m in methods):
                # Check if any argument is a variable (not constant string)
                args = getattr(ast_node, "arguments", [])
                tainted = False
                for arg in args:
                    stripped = arg.strip()
                    if stripped and not (
                        stripped.startswith(('"', "'"))
                        and stripped.endswith(stripped[0])
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
                            message=f"Potential template injection via `{
                                callee}` with variable template. Avoid user‑controlled templates.",
                            code_snippet=node.get("content", "").splitlines()[
                                ast_node.start_line - node.get("start_line", 1)
                            ],
                            cwe_id=self.cwe_id,
                        )
                    )
                break
        return findings

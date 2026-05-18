from typing import List, Dict, Any
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import CallNode

class InsecurePermissionsRule(BaseRule):
    @property
    def name(self) -> str:
        return "Insecure File Permissions"

    @property
    def severity(self) -> str:
        return "MEDIUM"

    @property
    def cwe_id(self) -> str:
        return "CWE-732"

    # Sinks per language (function names that change permissions)
    SINKS = {
        "python": ["os.chmod", "chmod"],
        "javascript": ["fs.chmodSync", "fs.chmod"],
        "go": ["os.Chmod"],
        "rust": ["std::fs::set_permissions"],
    }

    # Dangerous mode values (world‑writable)
    DANGEROUS_MODES = ["0o777", "0o666", "777", "666"]

    def check(self, chunk: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        lang = self._get_language(chunk)
        if not lang or lang not in self.SINKS:
            return []

        nodes = chunk.get("nodes", [])
        if not nodes:
            return []

        findings = []
        for node in nodes:
            if not isinstance(node, CallNode):
                continue

            callee = node.callee
            # Check if the callee is a known permission‑changing function
            if callee not in self.SINKS[lang]:
                continue

            # Get arguments (mode is usually the second argument)
            args = getattr(node, "arguments", [])
            mode_arg = args[1] if len(args) >= 2 else "unknown"

            # If any dangerous mode appears in the code string, report
            if any(mode in node.code for mode in self.DANGEROUS_MODES):
                findings.append(self._create_finding(chunk, node, callee, mode_arg))

        return findings

    def _create_finding(self, chunk, node, callee, mode):
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            file_path=chunk.get("file_path", ""),
            line_start=node.start_line,
            line_end=node.end_line,
            message=f"Insecure permission change via `{callee}` with mode: {mode} (world‑writable)",
            code_snippet=node.code,
            cwe_id=self.cwe_id,
        )
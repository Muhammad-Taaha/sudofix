from typing import List, Dict, Any
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import CallNode

class WeakPasswordHashRule(BaseRule):
    @property
    def name(self) -> str:
        return "Weak Cryptographic Hash"
    @property
    def severity(self) -> str:
        return "MEDIUM"
    @property
    def cwe_id(self) -> str:
        return "CWE-916"

    # Language‑specific weak hash functions (simplified)
    _weak_hashes = {
        "python": {"md5", "sha1"},
        "javascript": {"md5", "sha1"},
        "java": {"MD5", "SHA-1"},
        "go": {"md5", "sha1"},
    }

    def check(self, chunk: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        lang = self._get_language(chunk)
        if not lang or lang not in self._weak_hashes:
            return []
        nodes = chunk.get("nodes", [])
        findings = []
        for node in nodes:
            if not isinstance(node, CallNode):
                continue
            callee = node.callee.lower()
            for weak in self._weak_hashes[lang]:
                if weak in callee:
                    # Optional: only report if likely used for password
                    if any("password" in arg.lower() for arg in node.arguments) or "password" in node.code.lower():
                        findings.append(self._create_finding(chunk, node, weak))
                        break
        return findings

    def _create_finding(self, chunk, node, algo):
        # Positional arguments to match dataclass order:
        # rule_name, severity, file_path, line_start, line_end, message, code_snippet, cwe_id
        return Finding(
            self.name,
            self.severity,
            chunk.get("file_path", ""),
            node.start_line,
            node.end_line,
            f"Weak password hash algorithm '{algo}' used. Use bcrypt, Argon2, or PBKDF2.",
            node.code,
            self.cwe_id,
        )
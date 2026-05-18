from typing import List, Dict, Any
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import CallNode

class SessionFixationRule(BaseRule):
    @property
    def name(self) -> str:
        return "Session Fixation Vulnerability"
    @property
    def severity(self) -> str:
        return "HIGH"
    @property
    def cwe_id(self) -> str:
        return "CWE-384"

    # Language‑specific session regeneration patterns
    _regeneration_patterns = {
        "python": ["session.flush", "session.regenerate", "request.session.cycle_key"],
        "java": ["request.getSession().invalidate", "request.changeSessionId"],
        "javascript": ["req.session.regenerate", "req.session.destroy"],
    }

    def check(self, chunk, context):
        lang = self._get_language(chunk)
        if lang not in self._regeneration_patterns:
            return []
        nodes = chunk.get("nodes", [])
        # Look for login/authenticate calls
        login_found = False
        regen_found = False
        for node in nodes:
            if not isinstance(node, CallNode):
                continue
            callee = node.callee.lower()
            if "login" in callee or "authenticate" in callee:
                login_found = True
            for pattern in self._regeneration_patterns[lang]:
                if pattern in callee:
                    regen_found = True
        if login_found and not regen_found:
            return [self._create_finding(chunk)]
        return []

    def _create_finding(self, chunk):
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            file_path=chunk.get("file_path", ""),
            line_start=1,
            line_end=1,
            message="Session fixation possible – regenerate session ID after login.",
            code_snippet="",
            cwe_id=self.cwe_id,
        )
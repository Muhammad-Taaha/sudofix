from typing import List, Dict, Any
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import UnifiedNode

class MissingAuthDecoratorRule(BaseRule):
    @property
    def name(self) -> str:
        return "Missing Authentication Decorator"
    @property
    def severity(self) -> str:
        return "HIGH"
    @property
    def cwe_id(self) -> str:
        return "CWE-306"

    # Language/framework‑specific authentication markers
    _auth_markers = {
        "python": ["@login_required", "@permission_classes", "LoginRequiredMixin"],
        "java": ["@PreAuthorize", "@RolesAllowed", "@Secured"],
        "javascript": ["isAuthenticated", "ensureAuth", "authMiddleware"],
        "go": ["AuthRequired", "middleware.Auth"],
    }

    def check(self, chunk, context):
        lang = self._get_language(chunk)
        if lang not in self._auth_markers:
            return []
        nodes = chunk.get("nodes", [])
        findings = []
        for node in nodes:
            if node.node_type != "function":
                continue
            # Skip public endpoints (heuristic)
            name = getattr(node, "name", "")
            if name and name.lower() in ("login", "register", "public", "health", "ping"):
                continue
            code = node.code
            if not any(marker in code for marker in self._auth_markers[lang]):
                findings.append(self._create_finding(chunk, node))
        return findings

    def _create_finding(self, chunk, node):
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            file_path=chunk.get("file_path", ""),
            line_start=node.start_line,
            line_end=node.end_line,
            message=f"Function '{node.name}' has no authentication decorator / middleware.",
            code_snippet=node.code,
            cwe_id=self.cwe_id,
        )
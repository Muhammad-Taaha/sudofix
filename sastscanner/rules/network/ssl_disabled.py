from typing import List, Dict, Any
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import CallNode, AssignNode

class SslDisabledRule(BaseRule):
    @property
    def name(self) -> str:
        return "SSL/TLS Verification Disabled"
    @property
    def severity(self) -> str:
        return "HIGH"
    @property
    def cwe_id(self) -> str:
        return "CWE-295"

    def check(self, chunk, context):
        lang = self._get_language(chunk)
        nodes = chunk.get("nodes", [])
        findings = []
        for node in nodes:
            if lang == "python":
                if isinstance(node, CallNode) and "requests." in node.callee and "verify=False" in node.code:
                    findings.append(self._create_finding(chunk, node))
                if "ssl._create_unverified_context" in node.code or "check_hostname=False" in node.code:
                    findings.append(self._create_finding(chunk, node))
            elif lang in ("javascript", "js"):
                if isinstance(node, AssignNode) and "NODE_TLS_REJECT_UNAUTHORIZED" in node.code and "0" in node.value:
                    findings.append(self._create_finding(chunk, node))
            elif lang == "java":
                if isinstance(node, CallNode) and ("setHostnameVerifier" in node.callee and "ALLOW_ALL" in node.code):
                    findings.append(self._create_finding(chunk, node))
        return findings

    def _create_finding(self, chunk, node):
        return Finding(
            self.name,
            self.severity,
            chunk.get("file_path", ""),
            node.start_line,
            node.end_line,
            "SSL/TLS certificate verification disabled – insecure communication.",
            node.code,
            self.cwe_id,
        )
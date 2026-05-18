from typing import List, Dict, Any
import re
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import CallNode, AssignNode
from ..literal_helpers import is_constant_literal

class TlsNoVerifyRule(BaseRule):
    @property
    def name(self) -> str:
        return "SSL/TLS Certificate Verification Disabled"
    @property
    def severity(self) -> str:
        return "HIGH"
    @property
    def cwe_id(self) -> str:
        return "CWE-295"

    def check(self, chunk: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        lang = self._get_language(chunk)
        nodes = chunk.get("nodes", [])
        findings = []
        for node in nodes:
            # Python: requests.get(..., verify=False)
            if isinstance(node, CallNode):
                # Check if callee is a requests method and argument contains verify=False
                if "requests." in node.callee or "httpx." in node.callee:
                    if "verify=False" in node.code or "verify = False" in node.code:
                        findings.append(self._create_finding(chunk, node))
                # Also check for SSLContext with check_hostname=False
                if "check_hostname=False" in node.code or "verify_mode=ssl.CERT_NONE" in node.code:
                    findings.append(self._create_finding(chunk, node))
            # JavaScript: process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
            if lang in ("javascript", "js"):
                if isinstance(node, AssignNode) and "NODE_TLS_REJECT_UNAUTHORIZED" in node.code and "0" in node.value:
                    findings.append(self._create_finding(chunk, node))
            # Java: TrustManager that accepts all certificates – too complex, maybe skip.
        return findings

    def _create_finding(self, chunk, node):
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            file_path=chunk.get("file_path", ""),
            line_start=node.start_line,
            line_end=node.end_line,
            message="SSL/TLS certificate verification disabled – insecure communication.",
            code_snippet=node.code,
            cwe_id=self.cwe_id,
        )
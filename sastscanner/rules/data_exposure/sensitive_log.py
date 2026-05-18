from typing import List, Dict, Any
import re
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import CallNode

class SensitiveLogRule(BaseRule):
    @property
    def name(self) -> str:
        return "Sensitive Information in Logs"
    @property
    def severity(self) -> str:
        return "MEDIUM"
    @property
    def cwe_id(self) -> str:
        return "CWE-532"

    # Sensitive keywords (case‑insensitive)
    SENSITIVE_PATTERNS = [
        r"password", r"passwd", r"pwd",
        r"token", r"api_key", r"apikey",
        r"secret", r"credit_card", r"ssn",
    ]

    # Logging sinks per language
    SINKS = {
        "python": {"print", "logging.info", "logging.debug", "logger.info", "logger.debug"},
        "javascript": {"console.log", "console.info", "log"},
        "java": {"System.out.println", "logger.info", "log.debug"},
        "go": {"fmt.Println", "log.Println", "log.Print"},
    }

    def check(self, chunk, context):
        lang = self._get_language(chunk)
        if not lang or lang not in self.SINKS:
            return []
        nodes = chunk.get("nodes", [])
        findings = []
        for node in nodes:
            if not isinstance(node, CallNode):
                continue
            # Check if node is a logging call
            is_log_sink = any(sink in node.callee for sink in self.SINKS[lang])
            if not is_log_sink:
                continue
            # Check arguments for sensitive data
            for arg in node.arguments:
                for pattern in self.SENSITIVE_PATTERNS:
                    if re.search(pattern, arg, re.IGNORECASE):
                        findings.append(self._create_finding(chunk, node))
                        break
        return findings

    def _create_finding(self, chunk, node):
        return Finding(
            self.name,
            self.severity,
            chunk.get("file_path", ""),
            node.start_line,
            node.end_line,
            "Sensitive data (password/token/secret) logged – potential leak.",
            node.code,
            self.cwe_id,
        )
from typing import List, Dict, Any, Set
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import CallNode

class HttpNoTimeoutRule(BaseRule):
    @property
    def name(self) -> str:
        return "HTTP Request Without Timeout"
    @property
    def severity(self) -> str:
        return "LOW"
    @property
    def cwe_id(self) -> str:
        return "CWE-400"

    # Language‑specific patterns for requests without timeout
    _sink_cache: Dict[str, Set[str]] = {}
    _loaded = False

    @classmethod
    def _load_sinks(cls):
        if cls._loaded:
            return
        cls._sink_cache = {
            "python": {"requests.get", "requests.post", "requests.put", "requests.delete", "httpx.get"},
            "javascript": {"fetch", "axios.get", "axios.post"},
            "java": {"HttpClient.send", "HttpURLConnection.connect"},
            "go": {"http.Get", "http.Post"},
        }
        cls._loaded = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._load_sinks()

    def check(self, chunk, context):
        lang = self._get_language(chunk)
        if not lang or lang not in self._sink_cache:
            return []
        nodes = chunk.get("nodes", [])
        findings = []
        for node in nodes:
            if not isinstance(node, CallNode):
                continue
            if node.callee not in self._sink_cache[lang]:
                continue
            # Check if the call code contains a timeout parameter
            if "timeout" not in node.code.lower():
                findings.append(self._create_finding(chunk, node))
        return findings

    def _create_finding(self, chunk, node):
        return Finding(
            self.name,
            self.severity,
            chunk.get("file_path", ""),
            node.start_line,
            node.end_line,
            f"HTTP request in {node.callee} without timeout – may hang indefinitely.",
            node.code,
            self.cwe_id,
        )
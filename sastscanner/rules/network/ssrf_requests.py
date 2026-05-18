from typing import List, Dict, Any, Set
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import CallNode
from ..literal_helpers import is_constant_literal

class SsrfRule(BaseRule):
    @property
    def name(self) -> str:
        return "Server‑Side Request Forgery (SSRF)"
    @property
    def severity(self) -> str:
        return "MEDIUM"
    @property
    def cwe_id(self) -> str:
        return "CWE-918"

    _sink_cache: Dict[str, Set[str]] = {}
    _loaded = False

    @classmethod
    def _load_sinks(cls):
        if cls._loaded:
            return
        cls._sink_cache = {
            "python": {"requests.get", "requests.post", "httpx.get", "urllib.request.urlopen", "aiohttp.ClientSession.get"},
            "javascript": {"fetch", "axios.get", "http.get"},
            "java": {"HttpURLConnection", "HttpClient.send"},
            "go": {"http.Get", "http.Post"},
            "rust": {"reqwest::get"},
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
            args = getattr(node, "arguments", [])
            if args and not is_constant_literal(args[0]):
                findings.append(self._create_finding(chunk, node, node.callee))
        return findings

    def _create_finding(self, chunk, node, callee):
        return Finding(
            self.name,
            self.severity,
            chunk.get("file_path", ""),
            node.start_line,
            node.end_line,
            f"Potential SSRF: user‑controlled URL passed to {callee}.",
            node.code,
            self.cwe_id,
        )
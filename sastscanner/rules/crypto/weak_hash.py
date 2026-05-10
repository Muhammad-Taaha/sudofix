from typing import List, Dict, Any, Set
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import CallNode

class WeakHashRule(BaseRule):
    @property
    def name(self) -> str:
        return "Weak Cryptographic Hash"
    @property
    def severity(self) -> str:
        return "MEDIUM"
    @property
    def cwe_id(self) -> str:
        return "CWE-327"

    _sink_cache: Dict[str, Set[str]] = {}
    _loaded = False

    @classmethod
    def _load_sinks(cls):
        if cls._loaded:
            return
        cls._sink_cache = {
            "python": {"hashlib.md5", "hashlib.sha1", "md5", "sha1"},
            "javascript": {"md5", "sha1", "createHash('md5')", "createHash('sha1')"},
            "java": {"MD5", "SHA-1", "MessageDigest.getInstance(\"MD5\")", "MessageDigest.getInstance(\"SHA-1\")"},
            "go": {"md5.New", "sha1.New"},
            "rust": {"md5::compute", "sha1::compute"},
        }
        cls._loaded = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._load_sinks()

    def check(self, chunk: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        lang = self._get_language(chunk)
        if not lang or lang not in self._sink_cache:
            return []
        nodes = chunk.get("nodes", [])
        findings = []
        for node in nodes:
            if not isinstance(node, CallNode):
                continue
            callee = node.callee
            for weak in self._sink_cache[lang]:
                if weak in callee:
                    findings.append(self._create_finding(chunk, node, weak))
                    break
        return findings

    def _create_finding(self, chunk, node, algo):
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            file_path=chunk.get("file_path", ""),
            line_start=node.start_line,
            line_end=node.end_line,
            message=f"Weak hash algorithm '{algo}' used. Use SHA-256 or SHA-3.",
            code_snippet=node.code,
            cwe_id=self.cwe_id,
        )
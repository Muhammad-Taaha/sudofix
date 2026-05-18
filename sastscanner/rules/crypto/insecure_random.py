from typing import List, Dict, Any, Set
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import CallNode

class InsecureRandomRule(BaseRule):
    @property
    def name(self) -> str:
        return "Insecure Random Number Generation"
    @property
    def severity(self) -> str:
        return "MEDIUM"
    @property
    def cwe_id(self) -> str:
        return "CWE-330"

    _weak_random: Dict[str, Set[str]] = {}
    _loaded = False

    @classmethod
    def _load_sinks(cls):
        if cls._loaded:
            return
        cls._weak_random = {
            "python": {"random.random", "random.randint", "random.choice", "random.randrange"},
            "javascript": {"Math.random"},
            "java": {"java.util.Random", "Math.random"},
            "go": {"rand.Intn", "rand.Float64"},
            "rust": {"rand::random"},
        }
        cls._loaded = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._load_sinks()

    def check(self, chunk, context):
        lang = self._get_language(chunk)
        if not lang or lang not in self._weak_random:
            return []
        nodes = chunk.get("nodes", [])
        findings = []
        for node in nodes:
            if not isinstance(node, CallNode):
                continue
            callee = node.callee
            for weak in self._weak_random[lang]:
                if weak in callee:
                    findings.append(self._create_finding(chunk, node, weak))
                    break
        return findings

    def _create_finding(self, chunk, node, func):
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            file_path=chunk.get("file_path", ""),
            line_start=node.start_line,
            line_end=node.end_line,
            message=f"Insecure random number generator '{func}'. Use cryptographically secure PRNG (e.g., 'secrets' module in Python).",
            code_snippet=node.code,
            cwe_id=self.cwe_id,
        )
from typing import List, Dict, Any, Set
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import CallNode

class YamlUnsafeRule(BaseRule):
    @property
    def name(self) -> str:
        return "Unsafe YAML Deserialization"
    @property
    def severity(self) -> str:
        return "HIGH"
    @property
    def cwe_id(self) -> str:
        return "CWE-502"

    _sink_cache: Dict[str, Set[str]] = {}
    _loaded = False

    @classmethod
    def _load_sinks(cls):
        if cls._loaded:
            return
        cls._sink_cache = {
            "python": {"yaml.load", "yaml.full_load", "yaml.unsafe_load"},
            "javascript": {"js-yaml.load", "YAML.load", "parse"},
            "java": {"Yaml().load", "Yaml.load", "ObjectMapper.readValue"},
            "go": {"yaml.Unmarshal"},
            "rust": {"serde_yaml::from_str", "yaml::from_str"},
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
            for sink in self._sink_cache[lang]:
                if sink in node.callee:
                    # For Python, check if SafeLoader is used
                    if lang == "python":
                        if "Loader=yaml.SafeLoader" not in node.code and "Loader=SafeLoader" not in node.code:
                            findings.append(self._create_finding(chunk, node, sink))
                    else:
                        findings.append(self._create_finding(chunk, node, sink))
        return findings

    def _create_finding(self, chunk, node, sink):
        return Finding(
            self.name,
            self.severity,
            chunk.get("file_path", ""),
            node.start_line,
            node.end_line,
            f"Unsafe YAML deserialization using {sink} – may lead to code execution.",
            node.code,
            self.cwe_id,
        )
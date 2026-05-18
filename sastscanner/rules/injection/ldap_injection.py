import json
import re
from pathlib import Path
from typing import List, Dict, Set
from ...findings.finding import Finding
from ..base_rule import BaseRule
from parser.ast_nodes import CallNode
from ..literal_helpers import is_constant_literal

class LdapInjectionRule(BaseRule):
    @property
    def name(self) -> str:
        return "LDAP Injection"

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def cwe_id(self) -> str:
        return "CWE-90"

    _sink_cache: Dict[str, Set[str]] = {}
    _loaded = False

    @classmethod
    def _load_sinks(cls):
        if cls._loaded:
            return
        json_path = Path(__file__).parent.parent / "sinks2.json"
        if json_path.exists():
            with open(json_path) as f:
                data = json.load(f)
            for entry in data:
                lang = entry.get("language")
                name = entry.get("name")
                cwe = entry.get("cwe", "")
                if cwe == "CWE-90" or "ldap" in name.lower():
                    cls._sink_cache.setdefault(lang, set()).add(name)
        legacy = {
            "python": {"search", "search_s", "search_ext", "bind", "bind_s"},
            "java": {"search", "searchForEntry"},
            "javascript": {"search", "searchBase"},
        }
        for lang, names in legacy.items():
            cls._sink_cache.setdefault(lang, set()).update(names)
        cls._loaded = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._load_sinks()

    # No custom _get_language – uses BaseRule's implementation

    def check(self, chunk, context):
        lang = self._get_language(chunk)   # from BaseRule
        if not lang or lang not in self._sink_cache:
            return []

        nodes = chunk.get("nodes", [])
        findings = []

        for ast_node in nodes:
            if not isinstance(ast_node, CallNode):
                continue
            callee = ast_node.callee.split('.')[-1]
            if callee not in self._sink_cache[lang]:
                continue

            arguments = getattr(ast_node, "arguments", [])
            if arguments:
                for arg in arguments:
                    if not is_constant_literal(arg):
                        findings.append(self._create_finding(chunk, ast_node, callee))
                        break
            else:
                # Fallback: extract arguments from code string
                code = ast_node.code
                match = re.search(r'\((.*?)\)', code, re.DOTALL)
                if match:
                    args_str = match.group(1).strip()
                    if args_str:
                        parts = [p.strip() for p in args_str.split(',') if p.strip()]
                        for part in parts:
                            if not (part.startswith(('"', "'")) and part.endswith(('"', "'"))):
                                findings.append(self._create_finding(chunk, ast_node, callee))
                                break
                    else:
                        findings.append(self._create_finding(chunk, ast_node, callee))
                else:
                    findings.append(self._create_finding(chunk, ast_node, callee))

        return findings

    def _create_finding(self, chunk, ast_node, callee):
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            file_path=chunk.get("file_path", ""),
            line_start=ast_node.start_line,
            line_end=ast_node.end_line,
            message=f"Potential LDAP injection via `{callee}` with user input.",
            code_snippet=ast_node.code,
            cwe_id=self.cwe_id,
        )
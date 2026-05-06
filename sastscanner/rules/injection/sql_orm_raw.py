import json
from pathlib import Path
from typing import List, Dict, Any, Set
from ...findings.finding import Finding
from ..base_rule import BaseRule
from parser.ast_nodes import CallNode
from ..literal_helpers import is_constant_literal

class OrmRawSqlRule(BaseRule):
    @property
    def name(self) -> str:
        return "ORM Raw SQL Execution"

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def cwe_id(self) -> str:
        return "CWE-89"

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
                if cwe == "CWE-89" and name in ("raw", "execute", "executescript", "createNativeQuery", "rawQuery"):
                    cls._sink_cache.setdefault(lang, set()).add(name)
        # Legacy – ensure `raw` and `execute` are always present
       # In sql_orm_raw.py, change the legacy list to only include "raw" and "rawQuery"
        legacy = {
            "python": {"raw", "rawQuery"},
            "java": {"createNativeQuery", "executeNativeQuery", "rawQuery"},
            "go": {"Raw"},
        }
        for lang, names in legacy.items():
            cls._sink_cache.setdefault(lang, set()).update(names)
        cls._loaded = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._load_sinks()

    def check(self, node, context):
        lang = node.get("language", "").lower()
        if lang not in self._sink_cache:
            return []
        ast_node = node.get("ast_node")
        if not isinstance(ast_node, CallNode):
            return []
        callee = ast_node.callee.split('.')[-1]
        if callee not in self._sink_cache[lang]:
            return []
        # For raw SQL, any non‑literal argument → vulnerable
        if not ast_node.arguments:
            return [self._make_finding(node, ast_node, callee)]
        for arg in ast_node.arguments:
            if not is_constant_literal(arg):
                return [self._make_finding(node, ast_node, callee)]
        return []

    def _make_finding(self, node, ast_node, callee):
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            file_path=node.get("file_path", ""),
            line_start=ast_node.start_line,
            line_end=ast_node.end_line,
            message=f"Potential SQL injection via raw ORM method `{callee}` with user input.",
            code_snippet=ast_node.code,
            cwe_id=self.cwe_id,
        )
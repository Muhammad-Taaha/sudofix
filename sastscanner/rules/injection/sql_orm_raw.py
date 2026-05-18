import json
import re
from pathlib import Path
from typing import Dict, Set, List

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
                if cwe == "CWE-89":
                    if name in ("raw", "rawQuery", "createNativeQuery", "executeNativeQuery", "Raw"):
                        cls._sink_cache.setdefault(lang, set()).add(name)
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

    def check(self, chunk, context):
        lang = self._get_language(chunk)   # from base class
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
            # Check arguments
            arguments = getattr(ast_node, "arguments", [])
            if not arguments:
                findings.append(self._create_finding(chunk, ast_node, callee))
                continue
            query_arg = arguments[0]
            if not is_constant_literal(query_arg):
                findings.append(self._create_finding(chunk, ast_node, callee))
                continue
            # If query_arg is a constant string, check for safe placeholders
            query_str = str(query_arg)
            safe_placeholders = ["%s", "?", ":1", ":name"]
            if any(ph in query_str for ph in safe_placeholders):
                continue
            # If extra arguments exist without placeholders -> suspicious
            if len(arguments) > 1:
                findings.append(self._create_finding(chunk, ast_node, callee))
        return findings

    def _create_finding(self, chunk, ast_node, callee):
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            file_path=chunk.get("file_path", ""),
            line_start=ast_node.start_line,
            line_end=ast_node.end_line,
            message=f"Potential SQL injection via raw ORM method `{callee}` with user input.",
            code_snippet=ast_node.code,
            cwe_id=self.cwe_id,
        )
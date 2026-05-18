import json
import re
from pathlib import Path
from typing import List, Set, Dict
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import CallNode

class CommandInjectionRule(BaseRule):
    @property
    def name(self) -> str:
        return "Command Injection"

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def cwe_id(self) -> str:
        return "CWE-78"

    _sink_cache: Dict[str, Set[str]] = {}
    _loaded = False

    @classmethod
    def _load_sinks(cls):
        if cls._loaded:
            return
        current_dir = Path(__file__).parent.parent
        json_path = current_dir / "sinks2.json"
        if json_path.exists():
            with open(json_path) as f:
                data = json.load(f)
            for entry in data:
                lang = entry.get("language")
                name = entry.get("name")
                cwe = entry.get("cwe", "")
                if cwe == "CWE-78":
                    cls._sink_cache.setdefault(lang, set()).add(name)
        legacy = {
            "python": {"system", "popen", "Popen", "exec", "call", "check_call", "check_output", "run"},
            "javascript": {"exec", "execSync", "spawn", "fork"},
            "java": {"exec"},
            "go": {"Command", "CommandContext"},
            "php": {"shell_exec", "exec", "system", "passthru", "popen", "proc_open"},
            "ruby": {"system", "exec", "`"},
            "rust": {"new"},
            "c": {"system", "popen"},
            "cpp": {"system", "popen"},
        }
        for lang, names in legacy.items():
            cls._sink_cache.setdefault(lang, set()).update(names)
        cls._loaded = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._load_sinks()

    @staticmethod
    def _get_base_name(callee: str) -> str:
        return callee.split('.')[-1].replace('()', '')

    def check(self, chunk, context):
        nodes = chunk.get("nodes", [])
        if not nodes:
            return []

        # Determine language from the first node (all nodes in chunk share same language)
        lang = getattr(nodes[0], "language", "").lower()
        if not lang:
            # Fallback to chunk's language key if present
            lang = chunk.get("language", "").lower()
        if lang not in self._sink_cache:
            return []

        findings = []
        for ast_node in nodes:
            if not isinstance(ast_node, CallNode):
                continue

            base = self._get_base_name(ast_node.callee)
            if base not in self._sink_cache[lang]:
                continue

            # Simple heuristic: if the call's argument string contains any variable (not a quoted literal)
            code = ast_node.code
            match = re.search(r'\((.*)\)', code, re.DOTALL)
            if match:
                args_str = match.group(1).strip()
                if args_str:
                    parts = [p.strip() for p in args_str.split(',') if p.strip()]
                    for part in parts:
                        if not (part.startswith(('"', "'")) and part.endswith(('"', "'"))):
                            findings.append(self._create_finding(chunk, ast_node, ast_node.callee))
                            break
                else:
                    # No arguments – still a dangerous call (e.g., `os.system()`)
                    findings.append(self._create_finding(chunk, ast_node, ast_node.callee))
            else:
                # No parentheses – fallback: create finding anyway
                findings.append(self._create_finding(chunk, ast_node, ast_node.callee))

        return findings

    def _create_finding(self, chunk, ast_node, callee):
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            file_path=chunk.get("file_path", ""),
            line_start=ast_node.start_line,
            line_end=ast_node.end_line,
            message=f"Potential command injection via `{callee}` with user input.",
            code_snippet=ast_node.code,
            cwe_id=self.cwe_id,
        )
import re
from typing import Dict, List


class TaintRules:
    def __init__(self):

        self.sources: Dict[str, List[str]] = {
            "python": [r"\binput\s*\(", r"\bsys\.argv", r"\bos\.environ"],
            "javascript": [r"req\.(body|query|params)", r"document\.location"],
            "java": [r"request\.getParameter", r"Scanner"],
            "go": [r"r\.FormValue", r"os\.Getenv"],
            "cpp": [r"\bcin\b", r"\bscanf\b"],
            "rust": [r"std::env::args", r"stdin"],
        }

        self.sinks: Dict[str, List[str]] = {
            "python": [r"os\.system", r"subprocess\.", r"eval", r"exec", r"open"],
            "javascript": [r"eval", r"child_process", r"innerHTML"],
            "java": [r"Runtime\.getRuntime", r"ProcessBuilder"],
            "go": [r"exec\.Command", r"http\.Get"],
            "cpp": [r"system", r"execvp"],
            "rust": [r"Command::new"],
        }

        self.sanitizers: Dict[str, List[str]] = {
            "python": [r"html\.escape", r"bleach\.clean", r"re\.sub", r"urllib\.parse"],
            "javascript": [r"DOMPurify\.sanitize", r"encodeURIComponent"],
            "java": [r"StringEscapeUtils"],
            "go": [r"html\.EscapeString"],
            "cpp": [r"sanitize"],
            "rust": [r"escape"],
        }

    def is_source(self, name: str, lang: str) -> bool:
        return self._match(name, lang, self.sources)

    def is_sink(self, name: str, lang: str) -> bool:
        return self._match(name, lang, self.sinks)

    def is_sanitizer(self, name: str, lang: str) -> bool:
        return self._match(name, lang, self.sanitizers)

    def _match(self, name: str, lang: str, rules: dict):
        if lang not in rules:
            return False
        return any(re.search(p, name) for p in rules[lang])

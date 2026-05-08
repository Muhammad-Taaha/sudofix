import re
from typing import Dict, List


class TaintRules:
    def __init__(self):
        self.sources: Dict[str, List[str]] = {
            "python": [
                r"input",
                r"request\.(GET|POST|args|get_json)",
                r"sys\.argv"
            ],
            "javascript": [
                r"req\.body",
                r"req\.query",
                r"document\.location",
                r"window\.location"
            ],
            "java": [
                r"request\.getParameter",
                r"System\.in"
            ],
            "go": [
                r"r\.FormValue",
                r"r\.URL\.Query"
            ],
            "cpp": [
                r"cin",
                r"gets",
                r"scanf"
            ]
        }

        self.sinks: Dict[str, List[str]] = {
            "python": [
                r"os\.system",
                r"subprocess\.",
                r"eval",
                r"exec"
            ],
            "javascript": [
                r"eval",
                r"child_process\.exec",
                r"innerHTML"
            ],
            "java": [
                r"Runtime\.getRuntime\(\)\.exec"
            ],
            "go": [
                r"os/exec"
            ],
            "cpp": [
                r"system"
            ]
        }

    def is_source(self, name: str, lang: str) -> bool:
        return any(re.search(p, name) for p in self.sources.get(lang, []))

    def is_sink(self, name: str, lang: str) -> bool:
        return any(re.search(p, name) for p in self.sinks.get(lang, []))
from typing import List, Dict, Any
from ..base_rule import BaseRule
from ...findings.finding import Finding


class CommandInjectionRule(BaseRule):

    # Language-specific sinks: module/class patterns and function names
    SINKS = {
        "python": {
            "modules": ["os", "subprocess"],
            "functions": [
                "system",
                "popen",
                "call",
                "check_call",
                "check_output",
                "run",
            ],
            # For subprocess, we need to check if shell=True is used (optional)
        },
        "c": {"functions": ["system", "popen"]},
        "cpp": {"functions": ["system", "popen"]},
        "java": {
            "classes": ["Runtime", "ProcessBuilder"],
            "functions": ["exec", "start"],
        },
        "javascript": {
            "modules": ["child_process"],
            "functions": ["exec", "execSync", "spawn", "fork"],
        },
        "go": {"functions": ["Command"]},  # exec.Command
        # std::process::Command
        "rust": {"functions": ["new", "output", "status"]},
        "php": {"functions": ["shell_exec", "exec", "system", "passthru", "popen"]},
        "ruby": {"functions": ["system", "exec", "`"]},
    }

    @property
    def name(self) -> str:

        return "Command Injection"

    @property
    def severity(self):

        return "High"

    def cwe_id(self) -> str:

        return "CWE-78"

    def check(self, node: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        """
        node: a dict representing a code entity, must contain at least:
              - 'ast_node' (the UnifiedNode from your parser)
              - 'language', 'file_path', 'start_line', 'end_line', 'content'
        """
        findings = []

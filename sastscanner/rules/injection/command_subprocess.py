from typing import List, Dict, Any
from ..base_rule import BaseRule
from ...findings.finding import Finding


class CommandSubprocessRule(BaseRule):
    """
    Detects command injection across multiple languages when a shell is invoked
    or user input reaches dangerous process execution sinks.
    """

    # Language-specific sinks that indicate shell usage
    SINKS = {
        "python": {
            "modules": ["subprocess"],
            "functions": ["call", "Popen", "run", "check_call", "check_output"],
            "shell_flag": "shell=True",
        },
        "javascript": {
            "modules": ["child_process"],
            # spawn is safer (no shell by default)
            "functions": ["exec", "execSync"],
            "shell_implied": True,  # exec always uses shell
        },
        "java": {
            "classes": ["Runtime", "ProcessBuilder"],
            "functions": ["exec", "start"],
            # string concatenation
            "dangerous_pattern": r"Runtime\.getRuntime\(\)\.exec\([^,)]*\+",
        },
        "go": {
            "functions": ["Command"],
            # concatenation in args
            "dangerous_pattern": r"exec\.Command\(.*?\+",
        },
        "php": {
            "functions": ["shell_exec", "exec", "system", "passthru", "popen"],
            "shell_implied": True,
        },
        "ruby": {
            "functions": ["system", "exec", "`"],
            "shell_implied": True,
        },
        "rust": {
            "functions": ["new", "output", "status"],
            "dangerous_pattern": r"Command::new\([^)]*\+",  # concatenation
        },
    }

    @property
    def name(self) -> str:
        return "Command Injection via Subprocess/Shell"

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def cwe_id(self) -> str:
        return "CWE-78"

    def check(self, node: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        findings = []
        lang = node.get("language", "").lower()
        if lang not in self.SINKS:
            return findings

        ast_node = node.get("ast_node")
        if not ast_node or ast_node.node_type != "call":
            return findings

        callee = getattr(ast_node, "callee", "")
        sink_info = self.SINKS[lang]
        is_match = False

        # Check function name and module/class context
        func_match = any(f in callee for f in sink_info.get("functions", []))
        if not func_match:
            return findings

        # Module/class check
        if "modules" in sink_info:
            if not any(mod in callee for mod in sink_info["modules"]):
                return findings
        if "classes" in sink_info:
            if not any(cls in callee for cls in sink_info["classes"]):
                return findings

        # Determine if the call is dangerous (shell usage or tainted concatenation)
        dangerous = False

        # Case 1: explicit shell flag (Python)
        if "shell_flag" in sink_info:
            args = getattr(ast_node, "arguments", [])
            if any(sink_info["shell_flag"] in arg for arg in args):
                dangerous = True

        # Case 2: shell implied (e.g., child_process.exec, system in PHP)
        elif sink_info.get("shell_implied", False):
            dangerous = True

        # Case 3: dangerous pattern (e.g., string concatenation in Java/Go/Rust)
        elif "dangerous_pattern" in sink_info:
            import re

            source_code = node.get("content", "")
            # Find the line of the call
            lines = source_code.splitlines()
            line_idx = ast_node.start_line - node.get("start_line", 1)
            if 0 <= line_idx < len(lines):
                line = lines[line_idx]
                if re.search(sink_info["dangerous_pattern"], line):
                    dangerous = True

        if dangerous:
            findings.append(
                Finding(
                    rule_name=self.name,
                    severity=self.severity,
                    file_path=node.get("file_path", ""),
                    line_start=ast_node.start_line,
                    line_end=ast_node.end_line,
                    message=f"Potential command injection via `{
                        callee}` which invokes a shell or uses string concatenation. Avoid user input in shell commands.",
                    code_snippet=node.get("content", "").splitlines()[
                        ast_node.start_line - node.get("start_line", 1)
                    ],
                    cwe_id=self.cwe_id,
                )
            )

        return findings

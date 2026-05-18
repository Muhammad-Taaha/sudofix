# sastscanner/taint/taint_rules.py
# till now we are only sacing the variables the next step is to make the taint analysis for the datastruct
import re
from typing import Dict, List


class TaintRules:
    def __init__(self):
        # Sources: where untrusted user input enters the program
        self.sources: Dict[str, List[str]] = {
            "python": [
                r"input\s*\(",          # Python 2/3 input
                r"raw_input\s*\(",      # Python 2
                r"sys\.argv",
                r"os\.environ",
                r"getpass\.getpass",
                # Web frameworks
                r"request\.(GET|POST|get_json|args|form|data|cookies|headers)",
                r"flask\.request",
                r"django\.http\.request",
                r"self\.request",
            ],
            "javascript": [
                r"req\.(body|query|params|headers|cookies)",
                r"document\.location",
                r"window\.location",
                r"localStorage\.",
                r"sessionStorage\.",
                r"URLSearchParams",
                r"new\s+URL",
            ],
            "java": [
                r"request\.getParameter",
                r"request\.getParameterValues",
                r"request\.getQueryString",
                r"System\.in",
                r"Scanner\(",
                r"BufferedReader",
            ],
            "go": [
                r"r\.FormValue",
                r"r\.URL\.Query",
                r"r\.PostFormValue",
                r"os\.Getenv",
                r"bufio\.NewScanner",
            ],
            "cpp": [
                r"cin",
                r"gets",
                r"fgets",
                r"scanf",
                r"getenv",
            ],
            "rust": [
                r"std::env::args",
                r"std::io::stdin",
                r"read_line",
            ]
        }

        # Sinks: dangerous functions that should never receive tainted data
        self.sinks: Dict[str, List[str]] = {
            "python": [
                # Command injection
                r"os\.system",
                r"subprocess\.(run|call|Popen|check_output|check_call)",
                r"popen",
                r"spawn",
                r"os\.popen",
                r"commands\.getoutput",
                # SQL injection
                r"cursor\.execute",
                r"execute\s*\(",
                r"raw_connection\.cursor",
                r"sqlite3\.connect",
                r"MySQLdb\.connect",
                r"psycopg2\.connect",
                r"execute_many",
                # LDAP injection
                r"ldap\.initialize",
                r"ldap3\.Connection",
                r"ldap\.search",
                # Code injection
                r"eval\s*\(",
                r"exec\s*\(",
                r"__import__\s*\(",
                r"compile\s*\(",
                # NoSQL injection
                r"pymongo\.collection\.(find|insert|update|delete|aggregate)",
                # Template injection
                r"render_template_string",
                # Path traversal / File injection
                r"open\s*\(",
                r"file\.",
                # Deserialization
                r"pickle\.loads",
                r"yaml\.load",
                r"marshal\.loads",
                # XXE / XML
                r"xml\.etree",
                r"lxml\.etree\.parse",
            ],
            "javascript": [
                r"eval\s*\(",
                r"Function\s*\(",
                r"setTimeout\s*\(",
                r"setInterval\s*\(",
                r"child_process\.exec",
                r"child_process\.spawn",
                r"execSync",
                r"innerHTML\s*=",
                r"outerHTML\s*=",
                r"document\.write",
                r"document\.writeln",
                r"\.insertAdjacentHTML",
            ],
            "java": [
                r"Runtime\.getRuntime\(\)\.exec",
                r"ProcessBuilder",
                r"Statement\.execute",
                r"Statement\.executeQuery",
                r"PreparedStatement",
                r"ServletOutputStream\.print",
                r"PrintWriter\.print",
            ],
            "go": [
                r"exec\.Command",
                r"exec\.CommandContext",
                r"db\.Query",
                r"db\.Exec",
                r"db\.QueryRow",
                r"http\.Get",
                r"http\.Post",
            ],
            "cpp": [
                r"system\s*\(",
                r"popen\s*\(",
                r"execlp",
                r"execvp",
                r"ShellExecute",
            ],
            "rust": [
                r"std::process::Command",
                r"tokio::process::Command",
                r"std::process::Child",
            ]
        }

    def is_source(self, name: str, lang: str) -> bool:
        """Return True if the function/variable name matches a source pattern."""
        if lang not in self.sources:
            return False
        return any(re.search(p, name) for p in self.sources[lang])

    def is_sink(self, name: str, lang: str) -> bool:
        """Return True if the function/variable name matches a sink pattern."""
        if lang not in self.sinks:
            return False
        return any(re.search(p, name) for p in self.sinks[lang])
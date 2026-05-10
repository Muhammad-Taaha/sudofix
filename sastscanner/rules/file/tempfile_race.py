from typing import List, Dict, Any
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import CallNode

class TempfileRaceRule(BaseRule):
    @property
    def name(self) -> str:
        return "Insecure Temporary File Creation"

    @property
    def severity(self) -> str:
        return "MEDIUM"

    @property
    def cwe_id(self) -> str:
        return "CWE-377"

    DANGEROUS = {
        "python": ["tempfile.mktemp", "os.tmpnam", "os.tempnam"],
        "java": ["File.createTempFile"],  # actually safe if used correctly, but we flag when combined with insecure usage
        "javascript": ["tmp.tmpNameSync", "tmp.tmpName"],  # unsafe if not using `tmp.file`
        "go": ["ioutil.TempFile"],  # safe by default, but we can check if followed by chmod etc.
    }

    def check(self, chunk: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        lang = self._get_language(chunk)
        if lang not in self.DANGEROUS:
            return []

        nodes = chunk.get("nodes", [])
        findings = []
        for node in nodes:
            if not isinstance(node, CallNode):
                continue
            callee = node.callee
            if callee in self.DANGEROUS[lang]:
                findings.append(self._create_finding(chunk, node, callee))
        return findings

    def _create_finding(self, chunk, node, callee):
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            file_path=chunk.get("file_path", ""),
            line_start=node.start_line,
            line_end=node.end_line,
            message=f"Insecure temporary file function `{callee}` – use a race‑resistant alternative.",
            code_snippet=node.code,
            cwe_id=self.cwe_id,
        )
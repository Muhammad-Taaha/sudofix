#we are going to work on the insecure permisions for the creation of the safe fie 
# mainly going to focus on the change mode chmod 
from typing import List, Dict, Any
import re
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import CallNode

class InsecurePermissionsRule(BaseRule):
    @property 
    def name(self)->str :
        return "Insecure File Permissions"
    @property 
    def severity(self) -> str:
        return "MEDIUM"
    @property 
    def cwe_id(self) -> str:
        return "CWE-732"
    Sinks = {
        "python": ["os.chmod", "chmod"],
        "javascript": ["fs.chmodSync", "fs.chmod"],
        "go": ["os.Chmod"],
        "rust": ["std::fs::set_permissions"],
    }
    DANGEROUS_MODES = ["0o777", "0o666", "777", "666", "0o777", "0o666"]
    def check (self,chunk: Dict[str, Any], context: Dict[str, Any])->List[Finding]:
        try:
            lang = self._get_language(chunk)
        except:
            raise("the langugae not found in the nodes")
        if lang not in self.Sinks:
            return "the language not supported"
        try:
            nodes = chunk.get("nodes", [])
        except :
            raise "there are no nodes translated"
        findings = []
        for node in nodes:
            if not isinstance(node,CallNode):
                continue
            callee = node.callee
            is_sink = any(callee == sink or callee.startswith(sink + ".") for sink in self.SINKS[lang])
            if not is_sink: 
                print("no sinks matching in the sastscanner")
                continue 
            args = getattr(node, "arguments", [])
            if len(args) >= 2 :
                mode_arg = args[1]
                 # Simple check: if the code string contains dangerous octal numbers
                if any(mode in node.code for mode in self.DANGEROUS_MODES):
                    findings.append(self._create_finding(chunk, node, callee, mode_arg))
                else :
                    findings.append(self._create_finding(chunk, node, callee, "unknown"))
            return findings
    def _create_finding(self, chunk, node, callee, mode):
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            file_path=chunk.get("file_path", ""),
            line_start=node.start_line,
            line_end=node.end_line,
            message=f"Insecure permission change via `{callee}` with mode: {mode} (world-writable)",
            code_snippet=node.code,
            cwe_id=self.cwe_id,
        ) 


                
        



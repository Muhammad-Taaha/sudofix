from typing import List, Dict, Any
import re
from .base_rule import BaseRule
from ..findings.finding import Finding

class GenericSQLInjectionRule(BaseRule):
    @property
    def name(self) -> str:
        return "Generic SQL Injection"

    @property
    def severity(self) -> str:
        return "CRITICAL"

    @property
    def cwe_id(self) -> str:
        return "CWE-89"

    def check(self, chunk: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        findings = []
        content = chunk.get("content", "")
        
        # Check for simple concatenation of SQL queries
        sql_keywords = r"(?i)(SELECT|UPDATE|DELETE|INSERT|FROM|WHERE)"
        concat_pattern = r"\+\s*[a-zA-Z_][a-zA-Z0-9_]*|\$[a-zA-Z_][a-zA-Z0-9_]*|%s|{}"
        
        if re.search(sql_keywords, content) and re.search(concat_pattern, content):
            findings.append(Finding(
                rule_name=self.name,
                severity=self.severity,
                file_path=chunk.get("file_path", ""),
                line_start=chunk.get("start_line", 1),
                line_end=chunk.get("end_line", 1),
                message="Potential SQL Injection detected via query concatenation.",
                code_snippet=content.strip(),
                cwe_id=self.cwe_id
            ))
            
        return findings

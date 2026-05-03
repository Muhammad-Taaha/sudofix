from dataclasses import dataclass
from typing import optional


@dataclass
class Finding:
    rule_name: str
    severity: str  # HIGH, MEDIUM, LOW
    file_path: str
    line_start: int
    line_end: int
    message: str
    code_snippet: str
    cwe_id: Optional[str] = None

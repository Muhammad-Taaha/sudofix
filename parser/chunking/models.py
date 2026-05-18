from dataclasses import dataclass
from typing import Optional, Dict, Any


@dataclass
class Chunk:
    chunk_id: str
    file_path: str
    language: str
    chunk_type: str   # function / class / module
    symbol: Optional[str]
    content: str
    start_line: int
    end_line: int
    metadata: Dict[str, Any]

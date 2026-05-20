from typing import List, Dict, Any , Optional
from parser.ast_nodes import UnifiedNode
from dataclasses import dataclass
@dataclass
class Chunk:
    chunk_id: str
    file_path: str

    chunk_type: str   # function | class | flow | fallback
    symbol: Optional[str]

    nodes: List["UnifiedNode"]
    content: str

    start_line: int
    end_line: int

    metadata: dict
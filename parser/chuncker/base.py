# parser/chunker/base.py
from abc import ABC, abstractmethod
from typing import List, Dict

class BaseChunker(ABC):
    def __init__(self, file_path: str, content: str, metadata: Dict):
        self.file_path = file_path
        self.content = content
        self.metadata = metadata

    @abstractmethod
    def chunk(self) -> List[Dict]:
        """
        Returns a list of chunks, each a dictionary with:
        - chunk_id
        - file_path
        - language
        - symbol (function/class/section)
        - chunk_type
        - content
        - start_line
        - end_line
        - hash (content hash)
        """
        pass

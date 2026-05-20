from abc import ABC, abstractmethod
from typing import List
from parser.ast_nodes import UnifiedNode
from parser.chunking.models import Chunk


class BaseChunkStrategy(ABC):

    @abstractmethod
    def chunk(self, nodes: List[UnifiedNode], file_path: str) -> List[Chunk]:
        """
        Convert AST nodes into semantic chunks
        """
        pass

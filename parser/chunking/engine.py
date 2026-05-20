from parser.chunking.strategies.ast_semantic import ASTSemanticChunker
from parser.chunking.strategies.generic_chunking import GenericChunker
from parser.ast_nodes import UnifiedNode
from typing import List
class ChunkingEngine:
    def __init__(self):
        self.ast = ASTSemanticChunker()
        self.generic = GenericChunker()

    def chunk(self, nodes, language: str, file_path: str = None):

        if not isinstance(nodes, list):
           nodes = [nodes] if nodes else []  

        # --------------------------
        # AST PATH (ONLY if meaningful structure exists)
        # --------------------------
        if language in {"python", "java", "cpp", "go","rust","c","javascript"}:
            return self.ast.chunk(nodes)

        # --------------------------
        # DEFAULT PATH
        # --------------------------
        return self.generic.chunk(nodes, file_path)
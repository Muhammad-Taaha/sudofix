# this is the file that selects the chunker
# importing all the chunkers for the use
# refactored  only one class the ast_chunker
from parser.chunking.strategies.ast_semantic import ASTSemanticChunker
from parser.chunking.strategies.generic_chunker import GenericChunker


class ChunkerRegistry:

    def __init__(self):
        self.ast_chunker = ASTSemanticChunker()
        self.generic_chunker = GenericChunker()

    def get(self, language: str):

        # all code languages → AST
        if language in [
            "python", "java", "javascript",
            "go", "rust", "c", "cpp"
        ]:
            return self.ast_chunker

        # everything else → fallback
        return self.generic_chunker

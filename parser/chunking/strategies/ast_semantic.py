from typing import List
from parser.chunking.models import Chunk
from parser.ast_nodes import UnifiedNode
import hashlib

def hash_content(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

class ASTSemanticChunker:
    def chunk(self, root):
        # Normalize to list
        if isinstance(root, list):
            nodes = root
        else:
            nodes = [root]

        chunks = []

        def collect(node):
            if not hasattr(node, "node_type"):
                return
            if node.node_type in ["function", "class"]:
                # Create a Chunk object
                chunk = Chunk(
                    chunk_id=hash_content(node.code),
                    file_path=node.file_path,
                    chunk_type=node.node_type,
                    symbol=node.name,
                    nodes=[node],
                    content=node.code,
                    start_line=node.start_line,
                    end_line=node.end_line,
                    metadata={"language": node.language}
                )
                # Do not pass taint_findings here
                chunks.append(chunk)
            # Recurse into children
            for child in getattr(node, "children", []):
                collect(child)

        for node in nodes:
            collect(node)

        return chunks
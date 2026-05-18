from typing import List, Dict

import hashlib

from parser.chunking.base import BaseChunkStrategy


def hash_content(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class ASTSemanticChunker:

    def chunk(self, root_node, metadata):

        chunks = []
        all_nodes = root_node.walk_depth_first()

        seen_ranges = set()

        for node in all_nodes:

            # 🔥 heuristic: top-level meaningful blocks
            if node.node_type not in ["function", "class", "module"]:
                continue

            key = (node.start_line, node.end_line)
            if key in seen_ranges:
                continue

            seen_ranges.add(key)

            chunks.append({
                "chunk_id": node.node_id,
                "file_path": node.file_path,
                "language": node.language,
                "chunk_type": node.node_type,
                "symbol": node.name,
                "content": node.code,
                "start_line": node.start_line,
                "end_line": node.end_line,
                "metadata": metadata
            })

        return chunks

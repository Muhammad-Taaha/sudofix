# parser/chunker/generic_chunker.py
from .base import BaseChunker
from hashlib import sha256

def hash_content(content: str) -> str:
    return sha256(content.encode("utf-8")).hexdigest()

def stable_chunk_id(file_path: str, start_line: int, end_line: int) -> str:
    return sha256(f"{file_path}-{start_line}-{end_line}".encode("utf-8")).hexdigest()

class GenericChunker(BaseChunker):
    MAX_LINES = 50

    def chunk(self):
        lines = self.content.splitlines()
        chunks = []
        start = 0

        while start < len(lines):
            end = min(start + self.MAX_LINES, len(lines))
            chunk_content = "\n".join(lines[start:end])

            chunks.append({
                "chunk_id": stable_chunk_id(self.file_path, start+1, end),
                "file_path": self.file_path,
                "language": "generic",
                "symbol": None,
                "chunk_type": "block",
                "content": chunk_content,
                "start_line": start+1,
                "end_line": end,
                "hash": hash_content(chunk_content),

                # 🔥 CRITICAL FIX
                "nodes": []   # MUST exist even if empty
            })

            start = end

        return chunks

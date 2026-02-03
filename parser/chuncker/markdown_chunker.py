# parser/chunker/markdown_chunker.py
from .base import BaseChunker
from hashlib import sha256
import re

def hash_content(content: str) -> str:
    return sha256(content.encode("utf-8")).hexdigest()

def stable_chunk_id(file_path: str, start_line: int, end_line: int) -> str:
    return sha256(f"{file_path}-{start_line}-{end_line}".encode("utf-8")).hexdigest()

class MarkdownChunker(BaseChunker):
    def chunk(self):
        chunks = []
        lines = self.content.splitlines()
        start = 0
        title = "root"
        
        for i, line in enumerate(lines):
            header_match = re.match(r"^(#+)\s+(.*)", line)
            if header_match:
                if i > start:
                    # previous chunk
                    chunk_content = "\n".join(lines[start:i])
                    chunks.append({
                        "chunk_id": stable_chunk_id(self.file_path, start+1, i),
                        "file_path": self.file_path,
                        "language": "markdown",
                        "symbol": title,
                        "chunk_type": "section",
                        "content": chunk_content,
                        "start_line": start+1,
                        "end_line": i,
                        "hash": hash_content(chunk_content),
                    })
                start = i
                title = header_match.group(2)
        
        # last chunk
        if start < len(lines):
            chunk_content = "\n".join(lines[start:])
            chunks.append({
                "chunk_id": stable_chunk_id(self.file_path, start+1, len(lines)),
                "file_path": self.file_path,
                "language": "markdown",
                "symbol": title,
                "chunk_type": "section",
                "content": chunk_content,
                "start_line": start+1,
                "end_line": len(lines),
                "hash": hash_content(chunk_content),
            })
        
        return chunks

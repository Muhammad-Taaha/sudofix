# parser/chunker/python_chunker.py
import ast
from .base import BaseChunker
from hashlib import sha256


def hash_content(content: str) -> str:
    return sha256(content.encode("utf-8")).hexdigest()


def stable_chunk_id(file_path: str, start_line: int, end_line: int) -> str:
    return sha256(f"{file_path}-{start_line}-{end_line}".encode("utf-8")).hexdigest()


class PythonChunker(BaseChunker):
    def chunk(self):
        chunks = []
        tree = ast.parse(self.content)

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                start = node.lineno
                end = getattr(node, "end_lineno", start)
                source = "\n".join(self.content.splitlines()[start-1:end])

                chunks.append({
                    "chunk_id": stable_chunk_id(self.file_path, start, end),
                    "file_path": self.file_path,
                    "language": "python",
                    "symbol": node.name,
                    "chunk_type": type(node).__name__,
                    "content": source,
                    "start_line": start,
                    "end_line": end,
                    "hash": hash_content(source),
                })
        return chunks

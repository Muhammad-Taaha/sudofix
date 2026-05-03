from typing import List, Optional
from pathlib import Path
from parser.file_walker import RepoWalker
from parser.detectors import FileDetector
from parser.parser_factory import ParserFactory  # new import
import os


class RepoScanner:
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.walker = RepoWalker(self.repo_path)
        self.detector = FileDetector(repo_path)
        # self.parser = RepoParser(repo_path)   # <-- REMOVE

    def local_scanner(self):
        files = self.walker.get_tracked_files()
        parsed_chunks = []

        excluded_extensions = {
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".pdf",
            ".pyc",
            ".exe",
            ".bin",
            ".pkl",
        }
        excluded_files = {".env", "package-lock.json",
                          "yarn.lock", ".gitignore"}
        excluded_dirs = {".git", "__pycache__",
                         "node_modules", "venv", ".venv"}

        for file_path in files:
            full_path = os.path.join(self.repo_path, file_path)

            if not os.path.exists(full_path):
                print(f"⚠️ Warning: File not found on disk, skipping: {
                      file_path}")
                continue
            if os.path.isdir(full_path):
                continue

            ext = os.path.splitext(file_path)[1].lower()
            if ext in excluded_extensions or file_path in excluded_files:
                continue
            if any(d in file_path for d in excluded_dirs):
                continue

            # Get parser for this file
            parser = ParserFactory.get_parser(full_path)
            if not parser:
                print(f"⚠️ No parser for {
                    file_path} (language not supported) – skipping")
                continue

            # Parse the file into UnifiedNode objects
            try:
                nodes = parser.parse(full_path)
            except Exception as e:
                print(f"❌ Parse error in {file_path}: {e}")
                continue

            # Convert each UnifiedNode to a chunk dict (same format as before)
            for node in nodes:
                chunk = self._node_to_chunk(node, file_path)
                parsed_chunks.append(chunk)

        return parsed_chunks

    def github_webhook_scanner(self, changed_files: List[str]):
        parsed_chunks = []
        for relative_path in changed_files:
            file_path = self.repo_path / relative_path
            if not file_path.exists():
                continue

            parser = ParserFactory.get_parser(str(file_path))
            if not parser:
                continue

            try:
                nodes = parser.parse(str(file_path))
            except Exception:
                continue

            for node in nodes:
                chunk = self._node_to_chunk(node, str(file_path))
                parsed_chunks.append(chunk)
        return parsed_chunks

    # Helper method to convert UnifiedNode to old-style chunk dict
    def _node_to_chunk(self, node, file_path: str) -> dict:
        from parser.ast_nodes import UnifiedNode

        # Use same hash function as before
        import hashlib

        content = node.code
        chunk_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

        return {
            "repo_name": str(self.repo_path),
            "file_path": file_path,
            "file_name": Path(file_path).name,
            "file_extension": Path(file_path).suffix,
            "chunk_id": 0,  # you can assign sequentially if needed
            "chunk_hash": chunk_hash,
            "commit_hash": None,  # can be added later
            "parent_chunk_id": None,
            "start_line": node.start_line,
            "end_line": node.end_line,
            "content": content,
            "metadata": {
                "language": node.language,
                "role": "source",
                "parse_strategy": "tree-sitter" if node.language != "python" else "ast",
                "service": None,
            },
            "modified": True,
            "tags": [],
        }

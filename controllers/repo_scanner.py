from typing import List
from pathlib import Path
from parser.file_walker import RepoWalker
from parser.detectors import FileDetector
from parser.parser_factory import ParserFactory
from sastscanner.taint.taint_engine import TaintEngine
import os
import hashlib


class RepoScanner:
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.walker = RepoWalker(self.repo_path)
        self.detector = FileDetector(repo_path)

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

        excluded_files = {".env", "package-lock.json", "yarn.lock", ".gitignore"}

        excluded_dirs = {".git", "__pycache__", "node_modules", "venv", ".venv",    "target","node_modules",".git",
        "dist","build"}

        for file_path in files:
            full_path = os.path.join(self.repo_path, file_path)

            if not os.path.exists(full_path):
                continue

            if os.path.isdir(full_path):
                continue

            ext = os.path.splitext(file_path)[1].lower()
            if ext in excluded_extensions or file_path in excluded_files:
                continue

            if any(d in file_path for d in excluded_dirs):
                continue

            # -----------------------------
            # PARSE FILE → AST NODES
            # -----------------------------
            parser = ParserFactory.get_parser(full_path)
            if not parser:
                continue

            try:
                nodes = parser.parse(full_path)

                # 🔥 FIX: normalize nodes to list
                if not isinstance(nodes, list):
                    nodes = [nodes]

            except Exception as e:
                print(f"❌ Parse error in {file_path}: {e}")
                continue

            # -----------------------------
            # 🔥 TAINT ANALYSIS (per file)
            # -----------------------------
            taint_engine = TaintEngine()
            taint_findings = taint_engine.analyze(nodes)

            # -----------------------------
            # CONVERT NODES → CHUNKS
            # -----------------------------
            for node in nodes:
                chunk = self._node_to_chunk(node, file_path, taint_findings)
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

                # 🔥 FIX: normalize nodes
                if not isinstance(nodes, list):
                    nodes = [nodes]

            except Exception:
                continue

            # 🔥 TAINT ANALYSIS (per file)
            taint_engine = TaintEngine()
            taint_findings = taint_engine.analyze(nodes)

            for node in nodes:
                chunk = self._node_to_chunk(node, str(file_path), taint_findings)
                parsed_chunks.append(chunk)

        return parsed_chunks

    # -----------------------------
    # NODE → CHUNK CONVERSION
    # -----------------------------
    def _node_to_chunk(self, node, file_path: str, taint_findings=None) -> dict:
        content = getattr(node, "code", "")

        chunk_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

        return {
            "repo_name": str(self.repo_path),
            "file_path": file_path,
            "file_name": Path(file_path).name,
            "file_extension": Path(file_path).suffix,
            "chunk_id": 0,
            "chunk_hash": chunk_hash,
            "commit_hash": None,
            "parent_chunk_id": None,
            "start_line": getattr(node, "start_line", None),
            "end_line": getattr(node, "end_line", None),
            "content": content,
            # 🔥 TAINT FINDINGS ATTACHED
            "taint_findings": taint_findings or [],
            "metadata": {
                "language": getattr(node, "language", "unknown"),
                "role": "source",
                "parse_strategy": (
                    "tree-sitter"
                    if getattr(node, "language", "") != "python"
                    else "ast"
                ),
                "service": None,
            },
            "modified": True,
            "tags": [],
        }

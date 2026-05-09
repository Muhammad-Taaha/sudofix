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

    # ==============================
    # LOCAL SCANNER
    # ==============================
    def local_scanner(self):
        files = self.walker.get_tracked_files()
        parsed_chunks = []

        excluded_extensions = {
            ".png", ".jpg", ".jpeg", ".gif", ".pdf",
            ".pyc", ".exe", ".bin", ".pkl",
        }

        excluded_files = {
            ".env", "package-lock.json", "yarn.lock", ".gitignore"
        }

        excluded_dirs = {
            ".git", "__pycache__", "node_modules",
            "venv", ".venv", "target", "dist", "build"
        }

        for file_path in files:
            full_path = self.repo_path / file_path

            if not full_path.exists() or full_path.is_dir():
                continue

            if full_path.suffix.lower() in excluded_extensions:
                continue

            if file_path in excluded_files:
                continue

            if any(d in file_path for d in excluded_dirs):
                continue

            print(f"\n🧪 Parsing: {file_path}")

            # -----------------------------
            # PARSE FILE
            # -----------------------------
            parser = ParserFactory.get_parser(str(full_path))
            if not parser:
                continue

            try:
                nodes = parser.parse(str(full_path))

                if not isinstance(nodes, list):
                    nodes = [nodes]

            except Exception as e:
                print(f"❌ Parse error in {file_path}: {e}")
                continue

            # -----------------------------
            # SKIP EMPTY AST SAFELY
            # -----------------------------
            if not nodes:
                print("📄 EMPTY AST → skipping")
                continue

            # -----------------------------
            # TAINT ANALYSIS
            # -----------------------------
            taint_engine = TaintEngine()
            taint_findings = taint_engine.analyze(nodes)

            # -----------------------------
            # BUILD CHUNKS (FIXED: include nodes list)
            # -----------------------------
            for node in nodes:
                chunk = self._node_to_chunk(node, str(file_path), taint_findings)
                # 🔥 CRITICAL FIX: add the original node(s) to the chunk
                chunk["nodes"] = [node]   # <-- ensures main.py sees non‑empty AST
                parsed_chunks.append(chunk)

        return parsed_chunks

    # ==============================
    # GITHUB WEBHOOK SCANNER
    # ==============================
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
                if not isinstance(nodes, list):
                    nodes = [nodes]
            except Exception:
                continue

            if not nodes:
                continue

            taint_engine = TaintEngine()
            taint_findings = taint_engine.analyze(nodes)

            for node in nodes:
                chunk = self._node_to_chunk(node, str(file_path), taint_findings)
                chunk["nodes"] = [node]   # same fix
                parsed_chunks.append(chunk)

        return parsed_chunks

    # ==============================
    # NODE → CHUNK
    # ==============================
    def _node_to_chunk(self, node, file_path: str, taint_findings=None) -> dict:

        # -----------------------------
        # SAFE CONTENT EXTRACTION
        # -----------------------------
        content = (
            getattr(node, "code", None)
            or getattr(node, "text", None)
            or getattr(node, "value", None)
        )

        if content is None:
            content = ""

        content = str(content)

        # -----------------------------
        # SAFE HASHING
        # -----------------------------
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
            # 🔥 "nodes" will be added by the caller
        }
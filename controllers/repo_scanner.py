from typing import List
from pathlib import Path

from parser.file_walker import RepoWalker
from parser.detectors import FileDetector
from parser.parser_factory import ParserFactory
from parser.chunking.engine import ChunkingEngine

from parser.ast_nodes import ModuleNode
from sastscanner.taint.taint_engine import TaintEngine


class RepoScanner:
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)

        self.walker = RepoWalker(self.repo_path)
        self.detector = FileDetector(repo_path)

        # single shared engine
        self.chunking_engine = ChunkingEngine()

    # ==============================
    # LOCAL SCANNER
    # ==============================
    def local_scanner(self):
        files = self.walker.get_tracked_files()
        parsed_chunks = []

        excluded_extensions = {
            ".png", ".jpg", ".jpeg", ".gif", ".pdf",
            ".pyc", ".exe", ".bin", ".pkl", ".tflite"
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

            # ==============================
            # PARSE FILE → LIST OF NODES
            # ==============================
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

            if not nodes:
                print("📄 EMPTY AST → skipping")
                continue

            # ==============================
            # TAINT ANALYSIS
            # ==============================
            taint_engine = TaintEngine()
            taint_findings = taint_engine.analyze(nodes)

            language = nodes[0].language if nodes else "generic"

            # ==============================
            # BUILD ROOT NODE (IMPORTANT FIX)
            # ==============================
            root = ModuleNode(
                name=str(file_path),
                code="",
                file_path=str(full_path),
                start_line=0,
                end_line=0,
                language=language,
            )

            for node in nodes:
                root.add_child(node)

            # ==============================
            # CHUNKING (NOW CORRECT)
            # ==============================
            try:
                chunks = self.chunking_engine.chunk(root, language)
            except Exception as e:
                print(f"❌ Chunking failed for {file_path}: {e}")
                continue

            # ==============================
            # ATTACH TAINT + FORMAT OUTPUT
            # ==============================
            for chunk in chunks:
                chunk.taint_findings = taint_findings

                parsed_chunks.append({
                    "chunk_id": chunk.chunk_id,
                    "file_path": chunk.file_path,
                    "file_name": Path(chunk.file_path).name,
                    "file_extension": Path(chunk.file_path).suffix,
                    "chunk_type": chunk.chunk_type,
                    "symbol": chunk.symbol,
                    "content": chunk.content,
                    "start_line": chunk.start_line,
                    "end_line": chunk.end_line,
                    "chunk_hash": chunk.chunk_id,
                    "metadata": chunk.metadata,
                    "nodes": chunk.nodes,
                    "taint_findings": chunk.taint_findings,
                })

        return parsed_chunks

    # ==============================
    # GITHUB SCANNER
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

            language = nodes[0].language if nodes else "generic"

            # ==============================
            # BUILD ROOT NODE (FIXED HERE TOO)
            # ==============================
            root = ModuleNode(
                name=str(file_path),
                code="",
                file_path=str(file_path),
                start_line=0,
                end_line=0,
                language=language,
            )

            for node in nodes:
                root.add_child(node)

            # ==============================
            # CHUNKING
            # ==============================
            try:
                chunks = self.chunking_engine.chunk(root, language)
                print(f"for the debug of the chunks {chunks}")
                print("[DEBUG] root type in controller:", type(root))
            except Exception as e:
                print(f"❌ Chunking failed: {file_path} → {e}")
                continue

            for chunk in chunks:
                chunk.taint_findings = taint_findings

                parsed_chunks.append({
                    "chunk_id": chunk.chunk_id,
                    "file_path": chunk.file_path,
                    "file_name": Path(chunk.file_path).name,
                    "file_extension": Path(chunk.file_path).suffix,
                    "chunk_type": chunk.chunk_type,
                    "symbol": chunk.symbol,
                    "content": chunk.content,
                    "start_line": chunk.start_line,
                    "end_line": chunk.end_line,
                    "chunk_hash": chunk.chunk_id,
                    "metadata": chunk.metadata,
                    "nodes": chunk.nodes,
                    "taint_findings": chunk.taint_findings,
                })

        return parsed_chunks
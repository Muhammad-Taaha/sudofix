
import ast
import hashlib
import subprocess
from pathlib import Path
from typing import List, Dict, Optional
from .dependency_visitor import *
from tree_sitter import Parser

# Tree-sitter language bindings (Python 3.13 safe)
from tree_sitter_rust import language as rust_language
from tree_sitter_cpp import language as cpp_language


# --------------------------------
# Tree-sitter language registry
# --------------------------------
TS_LANGUAGES = {
    "rust": rust_language(),
    "cpp": cpp_language(),
}

# Node types per language
TS_TARGET_NODES = {
    "rust": {"function_item", "struct_item", "impl_item"},
    "cpp": {"function_definition", "class_specifier"},
}


# --------------------------------
# Helpers
# --------------------------------
def compute_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def get_latest_commit_hash(file_path: str) -> Optional[str]:
    try:
        result = subprocess.run(
            ["git", "log", "-n", "1", "--pretty=format:%H",
                "--", str(file_path)],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip() or None
    except Exception:
        return None


# --------------------------------
# RepoParser
# --------------------------------
class RepoParser:
    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.ts_parser = Parser()

    # -----------------------------
    # Python AST parsing
    # -----------------------------
    def parse_python(self, file_path: str, parent_chunk_map=None) -> List[Dict]:
        parent_chunk_map = parent_chunk_map or {}
        chunks = []

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()

        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []

        lines = source.splitlines()

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                # --- NEW RELATIONAL LOGIC ---
                visitor = DependencyVisitor()
                visitor.visit(node)

            # Extract signature for the database
                signature = ""
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    args = [a.arg for a in node.args.args]
                    signature = f"{node.name}({', '.join(args)})"

            # ... existing line/content logic ...

               # Inside parse_python loop:
                chunk_content = "\n".join(
                    lines[node.lineno-1: getattr(node, 'end_lineno', node.lineno)])
                chunk_hash = compute_hash(chunk_content)
                chunks.append(
                    self._build_chunk(
                        file_path=file_path,
                        chunk_id=len(chunks),
                        start_line=node.lineno,
                        end_line=getattr(node, 'end_lineno', node.lineno),
                        content=chunk_content,
                        # Hash is now just the chunk content
                        chunk_hash=chunk_hash,
                        parent_chunk_id=parent_chunk_map.get(
                            chunk_hash),
                        language="python",
                        strategy="ast"
                    )
                )
        return chunks

    # -----------------------------
    # Tree-sitter parsing (Rust / C++)
    # -----------------------------
    def parse_tree_sitter(self, file_path: str, language: str, parent_chunk_map=None) -> List[Dict]:
        parent_chunk_map = parent_chunk_map or {}

        if language not in TS_LANGUAGES:
            return self.parse_raw(file_path, parent_chunk_map)

        self.ts_parser.set_language(TS_LANGUAGES[language])

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()

        tree = self.ts_parser.parse(source.encode("utf-8"))
        lines = source.splitlines()
        chunks = []

        def walk(node):
            if node.type in TS_TARGET_NODES.get(language, set()):
                start = node.start_point[0] + 1
                end = node.end_point[0] + 1
                content = "\n".join(lines[start - 1: end])
                chunk_hash = compute_hash(content)

                chunks.append(
                    self._build_chunk(
                        file_path=file_path,
                        chunk_id=len(chunks),
                        start_line=start,
                        end_line=end,
                        content=content,
                        chunk_hash=chunk_hash,
                        parent_chunk_id=parent_chunk_map.get(chunk_hash),
                        language=language,
                        strategy="tree-sitter",
                    )
                )

            for child in node.children:
                walk(child)

        walk(tree.root_node)
        return chunks

    # -----------------------------
    # Raw text fallback
    # -----------------------------
    def parse_raw(self, file_path: str, parent_chunk_map=None) -> List[Dict]:
        parent_chunk_map = parent_chunk_map or {}

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()

        chunk_size = 500
        chunks = []

        for i in range(0, len(lines), chunk_size):
            content = "\n".join(lines[i: i + chunk_size])
            chunk_hash = compute_hash(content)

            chunks.append(
                self._build_chunk(
                    file_path=file_path,
                    chunk_id=len(chunks),
                    start_line=i + 1,
                    end_line=i + len(lines[i: i + chunk_size]),
                    content=content,
                    chunk_hash=chunk_hash,
                    parent_chunk_id=parent_chunk_map.get(chunk_hash),
                    language="raw-text",
                    strategy="raw-text",
                )
            )

        return chunks

    # -----------------------------
    # Unified interface

  # -----------------------------
    # Chunk builder (single source of truth)
    # -----------------------------

    def _build_chunk(
        self,
        file_path: str,
        chunk_id: int,
        start_line: int,
        end_line: int,
        content: str,
        chunk_hash: str,
        parent_chunk_id: Optional[int],
        language: str,
        strategy: str,
    ) -> Dict:
        return {
            "repo_name": self.repo_path,
            "file_path": str(file_path),
            "file_name": Path(file_path).name,
            "file_extension": Path(file_path).suffix,
            "chunk_id": chunk_id,
            "chunk_hash": chunk_hash,
            "commit_hash": get_latest_commit_hash(file_path),
            "parent_chunk_id": parent_chunk_id,
            "start_line": start_line,
            "end_line": end_line,
            "content": content,
            "metadata": {
                "language": language,
                "role": "source",
                "parse_strategy": strategy,
                "service": None,
            },
            "modified": parent_chunk_id is None,
            "tags": [],
        }

    def parse_file(self, metadata: Dict, parent_chunk_map=None) -> List[Dict]:
        parent_chunk_map = parent_chunk_map or {}
        file_path = metadata["file_path"]
        suffix = Path(file_path).suffix.lower()

    # 1. FORCE DETECTION based on extension
        if suffix == ".py":
            return self.parse_python(file_path, parent_chunk_map)

        elif suffix in [".rs", ".cpp", ".hpp", ".c"]:
            lang_map = {".rs": "rust", ".cpp": "cpp",
                        ".hpp": "cpp", ".c": "cpp"}
            return self.parse_tree_sitter(file_path, lang_map[suffix], parent_chunk_map)

    # 2. Fallback to raw text if it's not a supported code file
        return self.parse_raw(file_path, parent_chunk_map)

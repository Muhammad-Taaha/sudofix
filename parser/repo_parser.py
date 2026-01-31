import ast
import hashlib
from pathlib import Path
from typing import List, Dict
import subprocess
from tree_sitter import Language, Parser

# -------------------------------
# Tree-sitter setup
# -------------------------------
RUST_LANG = Language("my-languages.so", "rust")
CPP_LANG = Language("my-languages.so", "cpp")

TS_LANGUAGES = {
    "rust": RUST_LANG,
    "cpp": CPP_LANG
}

# -------------------------------
# Helper functions
# -------------------------------
def compute_hash(content: str) -> str:
    """Compute SHA256 hash of the given content"""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()

def get_latest_commit_hash(file_path: str) -> str:
    """Get the latest git commit hash for a file"""
    try:
        result = subprocess.run(
            ["git", "log", "-n", "1", "--pretty=format:%H", "--", str(file_path)],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None

# -------------------------------
# RepoParser
# -------------------------------
class RepoParser:
    def __init__(self, repo_name: str):
        self.repo_name = repo_name
        self.ts_parser = Parser()

    # -----------------------------
    # Python AST parsing
    # -----------------------------
    def parse_python(self, file_path: str, parent_chunk_map=None) -> List[Dict]:
        parent_chunk_map = parent_chunk_map or {}
        chunks = []
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()

        tree = ast.parse(source)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                start_line = node.lineno
                end_line = getattr(node, "end_lineno", node.lineno)
                chunk_source = "\n".join(source.splitlines()[start_line - 1:end_line])
                chunk_hash = compute_hash(chunk_source)

                # Check for parent chunk ID if exists
                parent_chunk_id = parent_chunk_map.get(chunk_hash)

                chunks.append({
                    "repo_name": self.repo_name,
                    "file_path": str(file_path),
                    "file_name": Path(file_path).name,
                    "file_extension": Path(file_path).suffix,
                    "chunk_id": len(chunks),
                    "chunk_hash": chunk_hash,
                    "commit_hash": get_latest_commit_hash(file_path),
                    "parent_chunk_id": parent_chunk_id,
                    "start_line": start_line,
                    "end_line": end_line,
                    "content": chunk_source,
                    "metadata": {
                        "language": "python",
                        "role": "source",
                        "parse_strategy": "ast",
                        "service": None
                    },
                    "modified": parent_chunk_id is None,
                    "tags": []
                })
        return chunks

    # -----------------------------
    # Tree-sitter parsing (Rust/C++)
    # -----------------------------
    def parse_tree_sitter(self, file_path: str, language_name: str, parent_chunk_map=None) -> List[Dict]:
        parent_chunk_map = parent_chunk_map or {}
        if language_name not in TS_LANGUAGES:
            return self.parse_raw(file_path, parent_chunk_map)

        self.ts_parser.set_language(TS_LANGUAGES[language_name])
        chunks = []
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()
        tree = self.ts_parser.parse(bytes(source, "utf8"))

        # Traverse the tree and extract function / struct nodes
        def walk(node, src_lines, chunks_list):
            if node.type in ("function_item", "struct_item", "impl_item"):
                start_line = node.start_point[0] + 1
                end_line = node.end_point[0] + 1
                chunk_source = "\n".join(src_lines[start_line - 1:end_line])
                chunk_hash = compute_hash(chunk_source)
                parent_chunk_id = parent_chunk_map.get(chunk_hash)
                chunks_list.append({
                    "repo_name": self.repo_name,
                    "file_path": str(file_path),
                    "file_name": Path(file_path).name,
                    "file_extension": Path(file_path).suffix,
                    "chunk_id": len(chunks_list),
                    "chunk_hash": chunk_hash,
                    "commit_hash": get_latest_commit_hash(file_path),
                    "parent_chunk_id": parent_chunk_id,
                    "start_line": start_line,
                    "end_line": end_line,
                    "content": chunk_source,
                    "metadata": {
                        "language": language_name,
                        "role": "source",
                        "parse_strategy": "tree-sitter",
                        "service": None
                    },
                    "modified": parent_chunk_id is None,
                    "tags": []
                })
            for child in node.children:
                walk(child, src_lines, chunks_list)

        src_lines = source.splitlines()
        walk(tree.root_node, src_lines, chunks)
        return chunks

    # -----------------------------
    # Raw-text parsing (Markdown, SQL, unknown)
    # -----------------------------
    def parse_raw(self, file_path: str, parent_chunk_map=None) -> List[Dict]:
        parent_chunk_map = parent_chunk_map or {}
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()
        lines = source.splitlines()
        chunk_size = 500
        chunks = []
        for i in range(0, len(lines), chunk_size):
            chunk_lines = lines[i:i + chunk_size]
            chunk_source = "\n".join(chunk_lines)
            chunk_hash = compute_hash(chunk_source)
            parent_chunk_id = parent_chunk_map.get(chunk_hash)
            chunks.append({
                "repo_name": self.repo_name,
                "file_path": str(file_path),
                "file_name": Path(file_path).name,
                "file_extension": Path(file_path).suffix,
                "chunk_id": len(chunks),
                "chunk_hash": chunk_hash,
                "commit_hash": get_latest_commit_hash(file_path),
                "parent_chunk_id": parent_chunk_id,
                "start_line": i + 1,
                "end_line": i + len(chunk_lines),
                "content": chunk_source,
                "metadata": {
                    "language": "raw-text",
                    "role": "source",
                    "parse_strategy": "raw-text",
                    "service": None
                },
                "modified": parent_chunk_id is None,
                "tags": []
            })
        return chunks

    # -----------------------------
    # Main parser interface
    # -----------------------------
    def parse_file(self, metadata: Dict, parent_chunk_map=None) -> List[Dict]:
        strategy = metadata.get("parse_strategy", "raw-text")
        file_path = metadata["file_path"]
        language = metadata.get("language", "unknown")

        if strategy == "ast" and language == "python":
            return self.parse_python(file_path, parent_chunk_map)
        elif strategy == "tree-sitter":
            return self.parse_tree_sitter(file_path, language, parent_chunk_map)
        else:
            return self.parse_raw(file_path, parent_chunk_map)


import hashlib
import subprocess
from pathlib import Path
from typing import List, Dict, Optional
from .dependency_visitor import *
from .chuncker.python_chuncker import PythonChunker
from .chuncker.markdown_chunker import MarkdownChunker
from .chuncker.generic_chunker import GenericChunker


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
# RepoParser - Language-agnostic file parser
# --------------------------------
class RepoParser:
    def __init__(self, repo_path: str):
        self.repo_path = repo_path

    def parse_file(self, metadata: Dict, parent_chunk_map=None) -> List[Dict]:
        """
        Main entry point for parsing files.
        Routes to appropriate parser based on file type.
        """
        parent_chunk_map = parent_chunk_map or {}
        file_path = metadata.get("file_path")
        file_name = Path(file_path).name
        suffix = Path(file_path).suffix.lower()

        if not Path(file_path).exists():
            print(f"⚠️ File not found: {file_path}")
            return []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            print(f"❌ Failed to read {file_name}: {e}")
            return []

        # Route to appropriate chunker based on language
        chunks = self._route_to_chunker(file_path, content, suffix)
        
        if not chunks:
            return []

        # Enrich chunks with repo-level metadata
        enriched_chunks = []
        for chunk in chunks:
            enriched_chunk = {
                **chunk,
                "repo_path": self.repo_path,
                "commit_hash": get_latest_commit_hash(file_path),
                "metadata": {
                    **chunk.get("metadata", {}),
                    "parent_chunk_id": parent_chunk_map.get(chunk.get("hash")),
                },
            }
            enriched_chunks.append(enriched_chunk)

        return enriched_chunks

    def _route_to_chunker(self, file_path: str, content: str, suffix: str) -> List[Dict]:
        """Route to appropriate chunker based on file extension."""
        file_name = Path(file_path).name

        # Python files
        if suffix == ".py":
            try:
                chunker = PythonChunker(file_path, content, {"language": "python"})
                chunks = chunker.chunk()
                print(f"✅ Parsed Python: {file_name} ({len(chunks)} chunks)")
                return chunks
            except Exception as e:
                print(f"⚠️ Python parsing failed for {file_name}, falling back: {e}")
                return self._generic_fallback(file_path, content)

        # Markdown files
        elif suffix in [".md", ".markdown", ".rst"]:
            try:
                chunker = MarkdownChunker(file_path, content, {"language": "markdown"})
                chunks = chunker.chunk()
                print(f"✅ Parsed Markdown: {file_name} ({len(chunks)} chunks)")
                return chunks
            except Exception as e:
                print(f"⚠️ Markdown parsing failed for {file_name}, falling back: {e}")
                return self._generic_fallback(file_path, content)

        # SQL, Config, and other text-based files
        elif suffix in [".sql", ".yaml", ".yml", ".json", ".txt", ".sh", ".env"]:
            try:
                chunker = GenericChunker(file_path, content, {"language": suffix.lstrip(".")})
                chunks = chunker.chunk()
                print(f"✅ Parsed Text: {file_name} ({len(chunks)} chunks)")
                return chunks
            except Exception as e:
                print(f"⚠️ Text parsing failed for {file_name}, falling back: {e}")
                return self._generic_fallback(file_path, content)

        # Unknown - generic fallback
        else:
            return self._generic_fallback(file_path, content)

    def _generic_fallback(self, file_path: str, content: str) -> List[Dict]:
        """Fallback to generic chunker for any file type."""
        try:
            chunker = GenericChunker(file_path, content, {"language": "generic"})
            chunks = chunker.chunk()
            file_name = Path(file_path).name
            print(f"✅ Parsed (generic): {file_name} ({len(chunks)} chunks)")
            return chunks
        except Exception as e:
            print(f"❌ Failed to parse {Path(file_path).name}: {e}")
            return []

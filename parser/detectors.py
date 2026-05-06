import os
import re
import yaml
from typing import Dict, Optional
from pathlib import Path

try:
    from pygments.lexers import guess_lexer_for_filename
except ImportError:
    guess_lexer_for_filename = None  # Optional fallback

# -------------------------------
# Load configuration from YAML
# -------------------------------
CONFIG_FILE = Path(__file__).parent / "parser_config.yaml"

if CONFIG_FILE.exists():
    with open(CONFIG_FILE) as f:
        CONFIG = yaml.safe_load(f)
else:
    # Default configuration
    CONFIG = {
        "languages": {
            ".py": {"strategy": "ast"},
            ".rs": {"strategy": "tree-sitter"},
            ".cpp": {"strategy": "tree-sitter"},
            ".c": {"strategy": "tree-sitter"},
            ".h": {"strategy": "tree-sitter"},
            ".hpp": {"strategy": "tree-sitter"},
            ".md": {"strategy": "markdown"},
            ".markdown": {"strategy": "markdown"},
            ".rst": {"strategy": "markdown"},
            ".sql": {"strategy": "generic"},
            ".yaml": {"strategy": "generic"},
            ".yml": {"strategy": "generic"},
            ".json": {"strategy": "generic"},
            ".txt": {"strategy": "generic"},
            ".sh": {"strategy": "generic"},
            ".env": {"strategy": "generic"},
        },
        "roles": {
            "entrypoint": ["main"],
            "test": ["test", "spec"],
            "documentation": [".md", ".rst", ".txt"],
        }
    }

# -------------------------------
# Detector Class
# -------------------------------
class FileDetector:
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)

    # -------------------------------
    # Detect file extension
    # -------------------------------
    @staticmethod
    def get_file_extension(file_path: str) -> str:
        return os.path.splitext(file_path)[1].lower()

    # -------------------------------
    # Detect language
    # -------------------------------
    @staticmethod
    def detect_language(file_path: str) -> str:
        ext = os.path.splitext(file_path)[1].lower()
        
        # Map extensions to proper language names
        LANGUAGE_MAP = {
            ".py": "python",
            ".rs": "rust",
            ".cpp": "cpp",
            ".c": "c",
            ".h": "c",
            ".hpp": "cpp",
            ".md": "markdown",
            ".markdown": "markdown",
            ".rst": "restructuredtext",
            ".sql": "sql",
            ".yaml": "yaml",
            ".yml": "yaml",
            ".json": "json",
            ".txt": "text",
            ".sh": "shell",
            ".bash": "shell",
            ".env": "shell",
        }
        
        if ext in LANGUAGE_MAP:
            return LANGUAGE_MAP[ext]

        # Optional: Use pygments for unknown extensions
        if guess_lexer_for_filename:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                lexer = guess_lexer_for_filename(file_path, content)
                return lexer.name.lower()
            except Exception:
                pass

        return "unknown"

    # -------------------------------
    # Detect role based on patterns
    # -------------------------------
    @staticmethod
    def detect_role(file_name: str) -> str:
        name_lower = file_name.lower()
        for role, patterns in CONFIG["roles"].items():
            for p in patterns:
                if re.search(p, name_lower):
                    return role
        return "source"  # default

    # -------------------------------
    # Detect parse strategy based on language
    # -------------------------------
    @staticmethod
    def detect_parse_strategy(language: str) -> str:
        # Map language names to parsing strategies
        STRATEGY_MAP = {
            "python": "ast",
            "rust": "tree-sitter",
            "cpp": "tree-sitter",
            "c": "tree-sitter",
            "markdown": "markdown",
            "restructuredtext": "markdown",
            "sql": "generic",
            "yaml": "generic",
            "json": "generic",
            "text": "generic",
            "shell": "generic",
            "generic": "generic",
        }
        return STRATEGY_MAP.get(language, "generic")

    # -------------------------------
    # Generate metadata for a file
    # -------------------------------
    def get_file_metadata(self, file_path: str) -> Dict:
        file_path = str(file_path)
        file_name = os.path.basename(file_path)
        file_extension = self.get_file_extension(file_path)
        language = self.detect_language(file_path)
        role = self.detect_role(file_name)
        parse_strategy = self.detect_parse_strategy(language)

        return {
            "file_path": file_path,
            "file_name": file_name,
            "file_extension": file_extension,
            "language": language,
            "role": role,
            "parse_strategy": parse_strategy,
        }

    # -------------------------------
    # Scan all files and return metadata
    # -------------------------------
    def scan_files(self, files: list) -> list:
        metadata_list = []
        for file_path in files:
            metadata = self.get_file_metadata(file_path)
            metadata_list.append(metadata)
        return metadata_list

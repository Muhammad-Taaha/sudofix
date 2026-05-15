"""
Extract import statements from source files and map them to known packages.
Supports Python, JavaScript/TypeScript, Java, Go, C/C++.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple

from sca.utils import get_logger

logger = get_logger(__name__)

# Map file extensions to language handlers
EXTENSION_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".c": "c",
    ".cpp": "c",
    ".cc": "c",
    ".cxx": "c",
    ".h": "c",
    ".hpp": "c",
}

# Regex patterns for import extraction (non‑AST languages)
JS_IMPORT_RE = re.compile(
    r'(?:import\s+(?:[\w*\s,{}]*from\s+)?|(?:const|let|var)\s+\w+\s*=\s*require\()["\']([^"\']+)["\']'
)
JAVA_IMPORT_RE = re.compile(r"^import\s+([\w.]+)(?:\.\*)?;")
GO_IMPORT_RE = re.compile(r'^\s*"([^"]+)"')
C_INCLUDE_RE = re.compile(r'#\s*include\s+[<"]([^>"]+)[>"]')


def map_imports(
    file_paths: List[Path],
) -> Dict[str, List[Tuple[str, int]]]:
    """
    Given a list of file paths, return a dict:
        package_name -> [(file_path, line_number), ...]

    Uses AST for Python, regex for others.
    """
    mapping: Dict[str, List[Tuple[str, int]]] = {}

    for fpath in file_paths:
        suffix = fpath.suffix.lower()
        lang = EXTENSION_MAP.get(suffix)
        if not lang:
            continue

        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            logger.warning("Cannot read file for import mapping", path=str(fpath))
            continue

        if lang == "python":
            imports = _extract_python_imports(content)
        elif lang in ("javascript", "typescript"):
            imports = _extract_js_imports(content)
        elif lang == "java":
            imports = _extract_java_imports(content)
        elif lang == "go":
            imports = _extract_go_imports(content)
        elif lang == "c":
            imports = _extract_c_includes(content)
        else:
            imports = []

        for pkg, lineno in imports:
            mapping.setdefault(pkg, []).append((str(fpath), lineno))

    return mapping


def _extract_python_imports(source: str) -> List[Tuple[str, int]]:
    """Use ast to extract imported module names (top‑level)."""
    results = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return results

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name.split(".")[0]  # only top-level package
                results.append((name, node.lineno))
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                name = node.module.split(".")[0]
                results.append((name, node.lineno))
    return results


def _extract_js_imports(source: str) -> List[Tuple[str, int]]:
    results = []
    for lineno, line in enumerate(source.splitlines(), 1):
        for m in JS_IMPORT_RE.findall(line):
            # m is the module path, take first part before /
            pkg = m.split("/")[0]
            if pkg.startswith("@"):
                # scoped packages: @scope/name -> @scope/name
                parts = m.split("/")
                if len(parts) >= 2:
                    pkg = f"{parts[0]}/{parts[1]}"
            results.append((pkg, lineno))
    return results


def _extract_java_imports(source: str) -> List[Tuple[str, int]]:
    results = []
    for lineno, line in enumerate(source.splitlines(), 1):
        m = JAVA_IMPORT_RE.match(line.strip())
        if m:
            # e.g., java.util.List → java
            pkg = m.group(1).split(".")[0]
            results.append((pkg, lineno))
    return results


def _extract_go_imports(source: str) -> List[Tuple[str, int]]:
    results = []
    in_import_block = False
    for lineno, line in enumerate(source.splitlines(), 1):
        stripped = line.strip()
        if stripped == "import (":
            in_import_block = True
            continue
        if in_import_block:
            if stripped == ")":
                in_import_block = False
                continue
            m = GO_IMPORT_RE.match(stripped)
            if m:
                path = m.group(1)
                # Package name is typically the last component
                pkg = path.split("/")[-1]
                results.append((pkg, lineno))
        else:
            m = re.match(r'import\s+"([^"]+)"', stripped)
            if m:
                path = m.group(1)
                pkg = path.split("/")[-1]
                results.append((pkg, lineno))
    return results


def _extract_c_includes(source: str) -> List[Tuple[str, int]]:
    results = []
    for lineno, line in enumerate(source.splitlines(), 1):
        m = C_INCLUDE_RE.match(line.strip())
        if m:
            # e.g., <stdio.h> → stdio
            inc = m.group(1)
            pkg = inc.split(".")[0]  # remove .h
            results.append((pkg, lineno))
    return results
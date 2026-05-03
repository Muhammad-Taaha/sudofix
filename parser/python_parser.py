import ast
from typing import List
from pathlib import Path
from .base_parser import BaseParser
from .ast_nodes import UnifiedNode


class PythonParser(BaseParser):
    def supported_extensions(self) -> List[str]:
        return [".py"]

    def parse(self, file_path: str) -> List[UnifiedNode]:
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []
        lines = source.splitlines()
        nodes = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = node.name
                start = node.lineno
                end = getattr(node, "end_lineno", node.lineno)
                code = "\n".join(lines[start - 1: end])
                node_type = "class" if isinstance(
                    node, ast.ClassDef) else "function"
                nodes.append(
                    UnifiedNode(
                        node_type=node_type,
                        name=name,
                        code=code,
                        file_path=file_path,
                        start_line=start,
                        end_line=end,
                        language="python",
                    )
                )
        return nodes

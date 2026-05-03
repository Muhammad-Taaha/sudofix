from tree_sitter import Language, Parser
import tree_sitter_rust as ts_rust
from pathlib import Path
from typing import List
from .base_parser import BaseParser
from .ast_nodes import UnifiedNode


class RustParser(BaseParser):
    def __init__(self):
        self.parser = Parser()
        self.parser.language = Language(ts_rust.language())

    def supported_extensions(self) -> List[str]:
        return [".rs"]

    def parse(self, file_path: str) -> List[UnifiedNode]:
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()
        tree = self.parser.parse(bytes(source, "utf-8"))
        root = tree.root_node
        lines = source.splitlines()
        nodes = []

        def walk(node):
            # Functions and methods (impl blocks)
            if node.type == "function_item":
                name_node = None
                for child in node.children:
                    if child.type == "identifier":
                        name_node = child
                        break
                name = name_node.text.decode(
                    "utf-8") if name_node else "<anonymous>"
                start = node.start_point[0] + 1
                end = node.end_point[0] + 1
                code = "\n".join(lines[start - 1: end])
                nodes.append(
                    UnifiedNode(
                        node_type="function",
                        name=name,
                        code=code,
                        file_path=file_path,
                        start_line=start,
                        end_line=end,
                        language="rust",
                    )
                )
            for child in node.children:
                walk(child)

        walk(root)
        return nodes

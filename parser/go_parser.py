from tree_sitter import Language, Parser  # Import from the library directly
import tree_sitter_go as ts_go
from pathlib import Path
from typing import List
from .base_parser import BaseParser
from .ast_nodes import UnifiedNode


class GoParser(BaseParser):
    def __init__(self):
        # Initialize the parser with the Go language
        self.ts_parser = Parser(Language(ts_go.language()))

    def supported_extensions(self) -> List[str]:
        return [".go"]

    def parse(
        self, file_path: str
    ) -> List[UnifiedNode]:  # Renamed from 'parser' to 'parse'
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()

        # Tree-sitter needs bytes
        tree = self.ts_parser.parse(bytes(source, "utf-8"))
        root = tree.root_node
        lines = source.splitlines()
        nodes = []

        def walk(node):
            # FIXED: 'declaration' spelled with an 'a'
            if node.type in ("function_declaration", "method_declaration"):
                name_node = None
                for child in node.children:
                    if child.type == "identifier":
                        name_node = child
                        break

                # Extract text from the source bytes using the node's range
                name = name_node.text.decode(
                    "utf-8") if name_node else "<anonymous>"

                # start_point is (row, column)
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
                        language="go",
                    )
                )

            for child in node.children:
                walk(child)

        walk(root)
        return nodes

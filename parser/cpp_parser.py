from tree_sitter import Language, Parser
import tree_sitter_cpp as ts_cpp
from pathlib import Path
from typing import Dict, List
from .base_parser import BaseParser
from .ast_nodes import UnifiedNode


class CppParser(BaseParser):

    def __init__(self):

        self.parser = Parser()

        self.parser.language = Language(ts_cpp.language())

    def supported_extensions(self) -> List[str]:

        return [".cpp", ".cc", ".cxx", ".hpp", ".h"]

    def parse(self, file_path: str) -> List[UnifiedNode]:

        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()
        tree = self.parser.parse(bytes(source, "utf-8"))
        root = tree.root_node
        lines = source.splitlines()
        nodes = []

        def walk(node):
            # Capture function definitions
            if node.type == "function_definition":
                # Find function declarator to get name
                name = "<anonymous>"
                for child in node.children:
                    if child.type == "function_declarator":
                        for sub in child.children:
                            if sub.type == "identifier":
                                name = sub.text.decode("utf-8")
                                break
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
                        language="cpp",
                    )
                )
            for child in node.children:
                walk(child)

        walk(root)
        return nodes

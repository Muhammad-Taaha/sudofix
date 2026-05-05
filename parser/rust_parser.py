from typing import Optional

import tree_sitter_rust as ts_rust
from tree_sitter import Language, Node, Parser

from .ast_nodes import (
    AssignNode,
    CallNode,
    IfNode,
    ImportNode,
    LoopNode,
    ModuleNode,
    ReturnNode,
    UnifiedNode,
)
from .base_parser import BaseParser


class RustParser(BaseParser):
    def __init__(self):
        self.parser = Parser()
        self.parser.language = Language(ts_rust.language())

    def supported_extensions(self):
        return [".rs"]

    def parse(self, file_path: str) -> ModuleNode:
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()
        source_bytes = source.encode("utf-8")
        tree = self.parser.parse(source_bytes)
        root = tree.root_node

        module = ModuleNode(
            name="module",
            code=source,
            file_path=file_path,
            start_line=1,
            end_line=max(1, len(source.splitlines())),
            language="rust",
        )
        for child in root.children:
            converted = self._convert_node(child, file_path, source_bytes)
            if converted:
                module.add_child(converted)
        return module

    def _convert_node(
        self, node: Node, file_path: str, source_bytes: bytes
    ) -> Optional[UnifiedNode]:
        node_type = node.type
        start = node.start_point[0] + 1
        end = node.end_point[0] + 1
        code = self._node_text(node, source_bytes)
        name = self._extract_name(node, source_bytes)

        if node_type in {"call_expression", "macro_invocation"}:
            converted: UnifiedNode = CallNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="rust",
                callee=self._extract_callee(node, source_bytes),
                arguments=self._extract_arguments(node, source_bytes),
            )
        elif node_type in {"assignment_expression", "let_declaration"}:
            targets, value = self._extract_assignment_parts(node, source_bytes)
            converted = AssignNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="rust",
                targets=targets,
                value=value,
            )
        elif node_type == "if_expression":
            converted = IfNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="rust",
                condition=self._field_text(node, "condition", source_bytes),
            )
        elif node_type in {"for_expression", "while_expression", "loop_expression"}:
            converted = LoopNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="rust",
                loop_kind=node_type.replace("_expression", ""),
                condition=self._field_text(node, "condition", source_bytes),
            )
        elif node_type == "return_expression":
            value = code.replace("return", "", 1).strip().rstrip(";")
            converted = ReturnNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="rust",
                value=value,
            )
        elif node_type == "use_declaration":
            converted = ImportNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="rust",
                module=code.replace("use", "", 1).strip().rstrip(";"),
                alias=None,
            )
        elif node_type in {"function_item", "closure_expression"}:
            converted = UnifiedNode(
                node_type="function",
                name=name,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="rust",
            )
        elif node_type in {"struct_item", "enum_item", "impl_item", "trait_item"}:
            converted = UnifiedNode(
                node_type="class",
                name=name,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="rust",
            )
        else:
            converted = UnifiedNode(
                node_type=node_type,
                name=name,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="rust",
            )

        for child in node.children:
            child_converted = self._convert_node(child, file_path, source_bytes)
            if child_converted:
                converted.add_child(child_converted)
        return converted

    def _extract_assignment_parts(self, node: Node, source_bytes: bytes):
        if node.type == "assignment_expression":
            left = self._field_text(node, "left", source_bytes)
            right = self._field_text(node, "right", source_bytes)
            return [left] if left else [], right
        if node.type == "let_declaration":
            left = self._field_text(node, "pattern", source_bytes)
            right = self._field_text(node, "value", source_bytes)
            return [left] if left else [], right
        return [], ""

    def _extract_callee(self, node: Node, source_bytes: bytes) -> str:
        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            if function:
                return self._node_text(function, source_bytes)
        if node.type == "macro_invocation":
            macro = node.child_by_field_name("macro")
            if macro:
                return self._node_text(macro, source_bytes)
        return self._node_text(node, source_bytes)

    def _extract_arguments(self, node: Node, source_bytes: bytes):
        if node.type == "call_expression":
            args_node = node.child_by_field_name("arguments")
            if not args_node:
                return []
            return [self._node_text(child, source_bytes) for child in args_node.children if child.type not in {"(", ")", ","}]
        if node.type == "macro_invocation":
            token_tree = node.child_by_field_name("token_tree")
            return [self._node_text(token_tree, source_bytes)] if token_tree else []
        return []

    def _extract_name(self, node: Node, source_bytes: bytes) -> Optional[str]:
        for field in ("name", "declarator", "pattern"):
            field_node = node.child_by_field_name(field)
            if field_node:
                return self._node_text(field_node, source_bytes)
        for child in node.children:
            if child.type == "identifier":
                return self._node_text(child, source_bytes)
        return None

    def _field_text(self, node: Node, field: str, source_bytes: bytes) -> str:
        field_node = node.child_by_field_name(field)
        if not field_node:
            return ""
        return self._node_text(field_node, source_bytes)

    @staticmethod
    def _node_text(node: Node, source_bytes: bytes) -> str:
        return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

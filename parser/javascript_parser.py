from typing import Optional

import tree_sitter_javascript as ts_js
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


class JavaScriptParser(BaseParser):
    def __init__(self):
        self.parser = Parser()
        self.parser.language = Language(ts_js.language())

    def supported_extensions(self):
        return [".js", ".jsx", ".mjs", ".cjs"]

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
            language="javascript",
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

        if node_type in {"call_expression", "new_expression"}:
            converted: UnifiedNode = CallNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="javascript",
                callee=self._extract_callee(node, source_bytes),
                arguments=self._extract_arguments(node, source_bytes),
            )
        elif node_type in {"assignment_expression", "variable_declarator"}:
            targets, value = self._extract_assignment_parts(node, source_bytes)
            converted = AssignNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="javascript",
                targets=targets,
                value=value,
            )
        elif node_type == "if_statement":
            converted = IfNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="javascript",
                condition=self._field_text(node, "condition", source_bytes),
            )
        elif node_type in {"for_statement", "for_in_statement", "for_of_statement", "while_statement", "do_statement"}:
            converted = LoopNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="javascript",
                loop_kind=node_type.replace("_statement", ""),
                condition=self._field_text(node, "condition", source_bytes),
            )
        elif node_type == "return_statement":
            value = code.replace("return", "", 1).strip().rstrip(";")
            converted = ReturnNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="javascript",
                value=value,
            )
        elif node_type == "import_statement":
            converted = ImportNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="javascript",
                module=code.replace("import", "", 1).strip().rstrip(";"),
                alias=None,
            )
        elif node_type in {"function_declaration", "generator_function_declaration", "arrow_function", "method_definition"}:
            converted = UnifiedNode(
                node_type="function",
                name=name,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="javascript",
            )
        elif node_type == "class_declaration":
            converted = UnifiedNode(
                node_type="class",
                name=name,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="javascript",
            )
        else:
            converted = UnifiedNode(
                node_type=node_type,
                name=name,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="javascript",
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
        if node.type == "variable_declarator":
            name = self._field_text(node, "name", source_bytes)
            value = self._field_text(node, "value", source_bytes)
            return [name] if name else [], value
        return [], ""

    def _extract_callee(self, node: Node, source_bytes: bytes) -> str:
        if node.type in {"call_expression", "new_expression"}:
            function_node = node.child_by_field_name("function") or node.child_by_field_name("constructor")
            if function_node:
                return self._node_text(function_node, source_bytes)
        return self._node_text(node, source_bytes)

    def _extract_arguments(self, node: Node, source_bytes: bytes):
        args_node = node.child_by_field_name("arguments")
        if not args_node:
            return []
        return [self._node_text(child, source_bytes) for child in args_node.children if child.type not in {"(", ")", ","}]

    def _extract_name(self, node: Node, source_bytes: bytes) -> Optional[str]:
        field_name = node.child_by_field_name("name")
        if field_name:
            return self._node_text(field_name, source_bytes)
        for child in node.children:
            if child.type in {"identifier", "property_identifier"}:
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

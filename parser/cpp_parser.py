from typing import List, Optional

import tree_sitter_cpp as ts_cpp
from tree_sitter import Language, Node, Parser

from .ast_nodes import (
    AssignNode,
    CallNode,
    IfNode,
    ImportNode,
    LoopNode,
    ReturnNode,
    UnifiedNode,
)
from .base_parser import BaseParser


class CppParser(BaseParser):
    def __init__(self):
        self.parser = Parser()
        self.parser.language = Language(ts_cpp.language())

    def supported_extensions(self):
        return [".cpp", ".cc", ".cxx", ".hpp", ".h"]

    # =====================================================
    # MAIN ENTRY → FLAT LIST OF MEANINGFUL NODES
    # =====================================================
    def parse(self, file_path: str) -> List[UnifiedNode]:
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()

        source_bytes = source.encode("utf-8")
        tree = self.parser.parse(source_bytes)
        nodes: List[UnifiedNode] = []

        for child in tree.root_node.children:
            self._collect_nodes(child, file_path, source_bytes, nodes)

        return nodes

    # =====================================================
    # COLLECTOR WITH FILTERING (SKIPS TRIVIAL NODES)
    # =====================================================
    def _collect_nodes(
        self,
        node: Node,
        file_path: str,
        source_bytes: bytes,
        out: List[UnifiedNode],
    ):
        # Skip trivial/punctuation/comment nodes
        if self._is_trivial_node(node.type):
            return

        # If it's a complete definition (function, class, etc.),
        # add it and do NOT recurse into its children.
        if self._is_complete_node(node.type):
            converted = self._convert_node(node, file_path, source_bytes)
            if converted:
                out.append(converted)
            return

        # Otherwise, recurse to find definitions inside
        for child in node.children:
            self._collect_nodes(child, file_path, source_bytes, out)

    # =====================================================
    # HELPERS: identify trivial and complete node types
    # =====================================================
    def _is_trivial_node(self, node_type: str) -> bool:
        """Node types that carry no semantic value for SAST/LLM."""
        trivial = {
            # Punctuation and separators
            "{", "}", "(", ")", "[", "]", ";", ",", ".",
            ":", "::", "->", "=>", "=", "!", "?", "@", "#", "~",
            # Comments
            "line_comment", "block_comment", "comment",
            # Syntax noise
            "identifier", "keyword", "type_identifier", "field_identifier",
            "primitive_type", "visibility_modifier", "attribute",
            "string_literal", "number_literal", "char_literal",
            "whitespace", "newline", "terminator",
            # C++ specific noise
            "template_argument_list", "template_parameter_list",
            "parameter_list", "parameter_declaration", "declarator",
            "abstract_declarator", "initializer_list", "initializer_pair",
        }
        return node_type in trivial

    def _is_complete_node(self, node_type: str) -> bool:
        """Node types that represent a complete top‑level definition."""
        complete = {
            "function_definition",
            "class_specifier",
            "struct_specifier",
            "union_specifier",
            "enum_specifier",
            "namespace_definition",
            "template_declaration",
            "using_declaration",
            "using_directive",
            "static_assert_declaration",
            "function_declarator",    # forward declaration
            "lambda_expression",      # treat as callable unit
        }
        return node_type in complete

    # =====================================================
    # CONVERSION (no recursion inside – flat output)
    # =====================================================
    def _convert_node(
        self, node: Node, file_path: str, source_bytes: bytes
    ) -> Optional[UnifiedNode]:
        node_type = node.type
        start = node.start_point[0] + 1
        end = node.end_point[0] + 1
        code = self._node_text(node, source_bytes)
        name = self._extract_name(node, source_bytes)

        if node_type == "call_expression":
            return CallNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="cpp",
                callee=self._field_text(node, "function", source_bytes) or code,
                arguments=self._extract_arguments(node, source_bytes),
            )
        elif node_type in {"assignment_expression", "init_declarator"}:
            targets, value = self._extract_assignment_parts(node, source_bytes)
            return AssignNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="cpp",
                targets=targets,
                value=value,
            )
        elif node_type == "if_statement":
            return IfNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="cpp",
                condition=self._field_text(node, "condition", source_bytes),
            )
        elif node_type in {"for_statement", "while_statement", "do_statement", "range_based_for_statement"}:
            return LoopNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="cpp",
                loop_kind=node_type.replace("_statement", ""),
                condition=self._field_text(node, "condition", source_bytes),
            )
        elif node_type == "return_statement":
            value = code.replace("return", "", 1).strip().rstrip(";")
            return ReturnNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="cpp",
                value=value,
            )
        elif node_type == "preproc_include":
            return ImportNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="cpp",
                module=code.replace("#include", "", 1).strip(),
                alias=None,
            )
        elif node_type in {"function_definition", "lambda_expression"}:
            return UnifiedNode(
                node_type="function",
                name=name,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="cpp",
            )
        elif node_type in {"class_specifier", "struct_specifier"}:
            return UnifiedNode(
                node_type="class",
                name=name,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="cpp",
            )
        else:
            # Fallback for any other node that made it through filtering
            return UnifiedNode(
                node_type=node_type,
                name=name,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="cpp",
            )

    # =====================================================
    # HELPERS (unchanged except minor improvements)
    # =====================================================
    def _extract_assignment_parts(self, node: Node, source_bytes: bytes):
        if node.type == "assignment_expression":
            left = self._field_text(node, "left", source_bytes)
            right = self._field_text(node, "right", source_bytes)
            return [left] if left else [], right
        if node.type == "init_declarator":
            left = self._field_text(node, "declarator", source_bytes)
            right = self._field_text(node, "value", source_bytes)
            return [left] if left else [], right
        return [], ""

    def _extract_arguments(self, node: Node, source_bytes: bytes):
        args_node = node.child_by_field_name("arguments")
        if not args_node:
            return []
        return [self._node_text(child, source_bytes) for child in args_node.children if child.type not in {"(", ")", ","}]

    def _extract_name(self, node: Node, source_bytes: bytes) -> Optional[str]:
        # Try declarator first
        declarator = node.child_by_field_name("declarator")
        if declarator:
            for child in declarator.children:
                if child.type in {"identifier", "field_identifier"}:
                    return self._node_text(child, source_bytes)
            return self._node_text(declarator, source_bytes)
        # Try other common fields
        for field in ("name", "declarator"):
            field_node = node.child_by_field_name(field)
            if field_node:
                return self._node_text(field_node, source_bytes)
        # Fallback: look for identifier children
        for child in node.children:
            if child.type in {"identifier", "type_identifier", "field_identifier"}:
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
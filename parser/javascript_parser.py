from typing import List, Optional

import tree_sitter_javascript as ts_js
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


class JavaScriptParser(BaseParser):
    def __init__(self):
        self.parser = Parser()
        self.parser.language = Language(ts_js.language())

    def supported_extensions(self):
        return [".js", ".jsx", ".mjs", ".cjs"]

    # =====================================================
    # MAIN ENTRY → FLAT LIST OF MEANINGFUL NODES
    # =====================================================
    def parse(self, file_path: str) -> List[UnifiedNode]:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                source = f.read()
        except Exception as e:
            print(f"❌ Failed to read {file_path}: {e}")
            return []

        source_bytes = source.encode("utf-8")

        try:
            tree = self.parser.parse(source_bytes)
        except Exception as e:
            print(f"❌ JS parse error in {file_path}: {e}")
            return []

        root = tree.root_node
        nodes: List[UnifiedNode] = []

        for child in root.children:
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
            "comment", "line_comment", "block_comment",
            # Syntax noise
            "identifier", "keyword", "string", "number", "regex",
            "template_string", "template_chars", "escape_sequence",
            "property_identifier", "private_property_identifier",
            "statement_identifier", "variable_declarator", "declarator",
            "whitespace", "newline", "terminator",
            # JS specific noise
            "formal_parameters", "parameter", "default_parameter",
            "rest_parameter", "object_pattern", "array_pattern",
            "spread_element", "parenthesized_expression",
        }
        return node_type in trivial

    def _is_complete_node(self, node_type: str) -> bool:
        """Node types that represent a complete top‑level or block‑level definition."""
        complete = {
            "function_declaration",
            "function_expression",
            "generator_function_declaration",
            "generator_function_expression",
            "arrow_function",
            "method_definition",
            "class_declaration",
            "class_expression",
            "export_statement",
            "import_statement",
            "variable_declaration",      # whole var/let/const block
            "if_statement",
            "for_statement",
            "for_in_statement",
            "for_of_statement",
            "while_statement",
            "do_statement",
            "switch_statement",
            "try_statement",
            "with_statement",
            "expression_statement",      # top-level expressions
            "return_statement",
            "throw_statement",
            "debugger_statement",
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

        # Call expressions / new
        if node_type in {"call_expression", "new_expression"}:
            return CallNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="javascript",
                callee=self._extract_callee(node, source_bytes),
                arguments=self._extract_arguments(node, source_bytes),
            )

        # Assignments / variable declarators
        elif node_type in {"assignment_expression", "variable_declarator"}:
            targets, value = self._extract_assignment_parts(node, source_bytes)
            return AssignNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="javascript",
                targets=targets,
                value=value,
            )

        # If statements
        elif node_type == "if_statement":
            return IfNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="javascript",
                condition=self._field_text(node, "condition", source_bytes),
            )

        # Loops
        elif node_type in {
            "for_statement",
            "for_in_statement",
            "for_of_statement",
            "while_statement",
            "do_statement",
        }:
            return LoopNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="javascript",
                loop_kind=node_type.replace("_statement", ""),
                condition=self._field_text(node, "condition", source_bytes),
            )

        # Return
        elif node_type == "return_statement":
            value = code.replace("return", "", 1).strip().rstrip(";")
            return ReturnNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="javascript",
                value=value,
            )

        # Import
        elif node_type == "import_statement":
            return ImportNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="javascript",
                module=code.replace("import", "", 1).strip().rstrip(";"),
                alias=None,
            )

        # Functions, arrows, methods
        elif node_type in {
            "function_declaration",
            "function_expression",
            "generator_function_declaration",
            "generator_function_expression",
            "arrow_function",
            "method_definition",
        }:
            return UnifiedNode(
                node_type="function",
                name=name,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="javascript",
            )

        # Classes
        elif node_type in {"class_declaration", "class_expression"}:
            return UnifiedNode(
                node_type="class",
                name=name,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="javascript",
            )

        # Variable declarations (whole var/let/const block)
        elif node_type == "variable_declaration":
            return UnifiedNode(
                node_type="variable_declaration",
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="javascript",
            )

        # Fallback for any other node that made it through filtering
        else:
            return UnifiedNode(
                node_type=node_type,
                name=name,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="javascript",
            )

    # =====================================================
    # HELPERS (unchanged from original, but used only for extraction)
    # =====================================================
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

        return [
            self._node_text(child, source_bytes)
            for child in args_node.children
            if child.type not in {"(", ")", ","}
        ]

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
        return source_bytes[node.start_byte:node.end_byte].decode(
            "utf-8", errors="replace"
        )
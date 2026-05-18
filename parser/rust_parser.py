from typing import Optional, List

import tree_sitter_rust as ts_rust
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


class RustParser(BaseParser):

    def __init__(self):
        self.parser = Parser()
        self.parser.language = Language(ts_rust.language())

    def supported_extensions(self):
        return [".rs"]

    # =====================================================
    # MAIN ENTRY → FLAT LIST OF DEFINITIONS ONLY
    # =====================================================
    def parse(self, file_path: str) -> List[UnifiedNode]:
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()
        source_bytes = source.encode("utf-8")
        tree = self.parser.parse(source_bytes)
        nodes: List[UnifiedNode] = []
        self._collect_nodes(tree.root_node, file_path, source_bytes, nodes)
        return nodes

    # =====================================================
    # SMART COLLECTOR – no recursion inside complete items
    # =====================================================
    def _collect_nodes(
        self,
        node: Node,
        file_path: str,
        source_bytes: bytes,
        out: List[UnifiedNode],
    ):
        # Skip punctuation, comments, and other noise
        if self._is_trivial_node(node.type):
            return

        # If this is a complete definition (function, struct, etc.),
        # add it and stop recursing into its children.
        if self._is_complete_node(node.type):
            converted = self._convert_node(node, file_path, source_bytes)
            if converted:
                out.append(converted)
            return  # 🔥 NO recursion – body is already inside the node's code

        # Otherwise, recurse to find complete items inside
        for child in node.children:
            self._collect_nodes(child, file_path, source_bytes, out)

    # =====================================================
    # HELPER: detect nodes that are complete, top‑level items
    # =====================================================
    def _is_complete_node(self, node_type: str) -> bool:
        complete_types = {
            "function_item",
            "struct_item",
            "enum_item",
            "impl_item",
            "trait_item",
            "const_item",
            "static_item",
            "type_item",
            "mod_item",
            "macro_invocation",     # macro definitions often count as items
            "use_declaration",
            "closure_expression",   # if you want each closure as a separate chunk
        }
        return node_type in complete_types

    # =====================================================
    # HELPER: skip trivial/punctuation nodes
    # =====================================================
    def _is_trivial_node(self, node_type: str) -> bool:
        trivial_types = {
            "{", "}", "(", ")", "[", "]", ";", ",", ".",
            ":", "::", "->", "=>", "=", "!", "?", "@", "#",
            "line_comment", "block_comment", "comment",
            "whitespace", "newline", "identifier", "keyword",
            "type_identifier", "field_identifier", "primitive_type",
            "visibility_modifier", "attribute_item", "attribute",
            "self", "super", "crate",
            "block", "statement_block", "declaration_list",
            "token_tree", "macro_rule", "macro_pattern",
            "parameters", "parameter", "reference_type", "type_arguments",
            "generic_type",
        }
        return node_type in trivial_types

    # =====================================================
    # CONVERSION (unchanged)
    # =====================================================
    def _convert_node(
        self, node: Node, file_path: str, source_bytes: bytes
    ) -> Optional[UnifiedNode]:

        node_type = node.type
        start = node.start_point[0] + 1
        end = node.end_point[0] + 1
        code = self._node_text(node, source_bytes)
        name = self._extract_name(node, source_bytes)

        if node_type in {"call_expression", "macro_invocation"}:
            return CallNode(
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
            return AssignNode(
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
            return IfNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="rust",
                condition=self._field_text(node, "condition", source_bytes),
            )

        elif node_type in {"for_expression", "while_expression", "loop_expression"}:
            return LoopNode(
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
            return ReturnNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="rust",
                value=value,
            )

        elif node_type == "use_declaration":
            return ImportNode(
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
            return UnifiedNode(
                node_type="function",
                name=name,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="rust",
            )

        elif node_type in {"struct_item", "enum_item", "impl_item", "trait_item"}:
            return UnifiedNode(
                node_type="class",
                name=name,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="rust",
            )

        # For any other node that reached here (shouldn't happen after complete/trivial filters)
        return UnifiedNode(
            node_type=node_type,
            name=name,
            code=code,
            file_path=file_path,
            start_line=start,
            end_line=end,
            language="rust",
        )

    # =====================================================
    # HELPERS (unchanged)
    # =====================================================
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
            fn = node.child_by_field_name("function")
            if fn:
                return self._node_text(fn, source_bytes)

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
            return [
                self._node_text(c, source_bytes)
                for c in args_node.children
                if c.type not in {"(", ")", ","}
            ]

        if node.type == "macro_invocation":
            t = node.child_by_field_name("token_tree")
            return [self._node_text(t, source_bytes)] if t else []

        return []

    def _extract_name(self, node: Node, source_bytes: bytes) -> Optional[str]:
        for field in ("name", "declarator", "pattern"):
            f = node.child_by_field_name(field)
            if f:
                return self._node_text(f, source_bytes)

        for child in node.children:
            if child.type == "identifier":
                return self._node_text(child, source_bytes)

        return None

    def _field_text(self, node: Node, field: str, source_bytes: bytes) -> str:
        f = node.child_by_field_name(field)
        return self._node_text(f, source_bytes) if f else ""

    @staticmethod
    def _node_text(node: Node, source_bytes: bytes) -> str:
        return source_bytes[node.start_byte:node.end_byte].decode(
            "utf-8", errors="replace"
        )
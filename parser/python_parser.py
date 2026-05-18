import ast
from typing import List, Optional

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


class PythonParser(BaseParser):

    def supported_extensions(self) -> List[str]:
        return [".py"]

    # ==============================
    # MAIN ENTRY
    # ==============================
    def parse(self, file_path: str) -> List[UnifiedNode]:
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()

        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []

        nodes: List[UnifiedNode] = []

        for node in ast.walk(tree):   # flat traversal
            converted = self._convert_node(node, file_path, source)
            if converted:
                nodes.append(converted)

        return nodes

    # ==============================
    # CONVERSION
    # ==============================
    def _convert_node(
        self,
        py_node: ast.AST,
        file_path: str,
        source: str,
    ) -> Optional[UnifiedNode]:

        start = getattr(py_node, "lineno", 1)
        end = getattr(py_node, "end_lineno", start)
        code = ast.get_source_segment(source, py_node) or ""

        if isinstance(py_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return UnifiedNode(
                node_type="function",
                name=py_node.name,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="python",
            )

        elif isinstance(py_node, ast.ClassDef):
            return UnifiedNode(
                node_type="class",
                name=py_node.name,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="python",
            )

        elif isinstance(py_node, ast.Call):
            return CallNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="python",
                callee=self._expr_to_str(py_node.func),
                arguments=self._call_arguments(py_node),
            )

        elif isinstance(py_node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            return AssignNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="python",
                targets=self._assignment_targets(py_node),
                value=self._assignment_value(py_node),
            )

        elif isinstance(py_node, ast.If):
            return IfNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="python",
                condition=self._expr_to_str(py_node.test),
            )

        elif isinstance(py_node, (ast.For, ast.AsyncFor, ast.While)):
            return LoopNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="python",
                loop_kind=type(py_node).__name__.lower(),
                condition=self._expr_to_str(getattr(py_node, "test", None)),
            )

        elif isinstance(py_node, (ast.Import, ast.ImportFrom)):
            return ImportNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="python",
                module=getattr(py_node, "module", "") or "",
                alias="",
            )

        elif isinstance(py_node, ast.Return):
            return ReturnNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="python",
                value=self._expr_to_str(py_node.value),
            )

        return None

    # ==============================
    # HELPERS
    # ==============================
    @staticmethod
    def _expr_to_str(expr: Optional[ast.AST]) -> str:
        if expr is None:
            return ""
        # Handle variable names directly – they become `user_cmd`, not `'user_cmd'`
        if isinstance(expr, ast.Name):
            return expr.id
        try:
            return ast.unparse(expr)
        except Exception:
            return ""

    def _call_arguments(self, node: ast.Call) -> List[str]:
        args = [self._expr_to_str(a) for a in node.args]
        kwargs = [f"{kw.arg}={self._expr_to_str(kw.value)}" for kw in node.keywords if kw.arg]
        # Debug print (remove after confirming it works)
        print(f"DEBUG: args = {args}, kwargs = {kwargs}")
        return args + kwargs

    def _assignment_targets(self, node: ast.AST) -> List[str]:
        if isinstance(node, ast.Assign):
            return [self._expr_to_str(t) for t in node.targets]
        if isinstance(node, ast.AnnAssign):
            return [self._expr_to_str(node.target)]
        if isinstance(node, ast.AugAssign):
            return [self._expr_to_str(node.target)]
        return []

    def _assignment_value(self, node: ast.AST) -> str:
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            return self._expr_to_str(getattr(node, "value", None))
        return ""
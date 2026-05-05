import ast
from typing import List, Optional

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


class PythonParser(BaseParser):
    def supported_extensions(self) -> List[str]:
        return [".py"]

    def parse(self, file_path: str) -> ModuleNode:
        """
        Parse a Python file into a full hierarchical AST of UnifiedNode objects.
        Returns a ModuleNode root that contains all descendants.
        """
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()

        try:
            tree = ast.parse(source)
        except SyntaxError:
            return ModuleNode(
                name="module",
                code=source,
                file_path=file_path,
                start_line=1,
                end_line=max(1, len(source.splitlines())),
                language="python",
            )

        module_node = ModuleNode(
            name="module",
            code=source,
            file_path=file_path,
            start_line=1,
            end_line=max(1, len(source.splitlines())),
            language="python",
        )

        root_converted = self._convert_node(tree, file_path, source)
        if root_converted:
            for child in root_converted.children:
                module_node.add_child(child)

        return module_node

    def _convert_node(
        self,
        py_node: ast.AST,
        file_path: str,
        source: str,
    ) -> Optional[UnifiedNode]:
        """Recursively convert a Python AST node into a UnifiedNode tree."""
        if isinstance(py_node, ast.Module):
            module = ModuleNode(
                name="module",
                code=source,
                file_path=file_path,
                start_line=1,
                end_line=max(1, len(source.splitlines())),
                language="python",
            )
            self._attach_children(module, py_node, file_path, source)
            return module

        start = getattr(py_node, "lineno", 1)
        end = getattr(py_node, "end_lineno", start)
        code = ast.get_source_segment(source, py_node) or ""

        if isinstance(py_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            converted = UnifiedNode(
                node_type="function",
                name=py_node.name,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="python",
            )
        elif isinstance(py_node, ast.ClassDef):
            converted = UnifiedNode(
                node_type="class",
                name=py_node.name,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="python",
            )
        elif isinstance(py_node, ast.Call):
            converted = CallNode(
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
            converted = AssignNode(
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
            converted = IfNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="python",
                condition=self._expr_to_str(py_node.test),
            )
        elif isinstance(py_node, (ast.For, ast.AsyncFor)):
            converted = LoopNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="python",
                loop_kind="for",
                condition=f"{self._expr_to_str(py_node.target)} in {self._expr_to_str(py_node.iter)}",
            )
        elif isinstance(py_node, ast.While):
            converted = LoopNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="python",
                loop_kind="while",
                condition=self._expr_to_str(py_node.test),
            )
        elif isinstance(py_node, (ast.Import, ast.ImportFrom)):
            module_name = getattr(py_node, "module", "") or ""
            alias_name = None
            if getattr(py_node, "names", None):
                alias_name = ", ".join(
                    alias.name if alias.asname is None else f"{alias.name} as {alias.asname}"
                    for alias in py_node.names
                )
                if isinstance(py_node, ast.Import):
                    module_name = alias_name
            converted = ImportNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="python",
                module=module_name,
                alias=alias_name,
            )
        elif isinstance(py_node, ast.Return):
            converted = ReturnNode(
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="python",
                value=self._expr_to_str(py_node.value),
            )
        else:
            converted = UnifiedNode(
                node_type=type(py_node).__name__.lower(),
                name=None,
                code=code,
                file_path=file_path,
                start_line=start,
                end_line=end,
                language="python",
            )

        self._attach_children(converted, py_node, file_path, source)
        return converted

    def _attach_children(
        self,
        parent: UnifiedNode,
        py_node: ast.AST,
        file_path: str,
        source: str,
    ) -> None:
        """Convert and attach direct child AST nodes recursively."""
        for child in ast.iter_child_nodes(py_node):
            converted_child = self._convert_node(child, file_path, source)
            if converted_child:
                parent.add_child(converted_child)

    @staticmethod
    def _expr_to_str(expr: Optional[ast.AST]) -> str:
        if expr is None:
            return ""
        try:
            return ast.unparse(expr)
        except Exception:
            return ""

    def _call_arguments(self, node: ast.Call) -> List[str]:
        args = [self._expr_to_str(arg) for arg in node.args]
        kwargs = [f"{kw.arg}={self._expr_to_str(kw.value)}" for kw in node.keywords if kw.arg]
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
        if isinstance(node, ast.Assign):
            return self._expr_to_str(node.value)
        if isinstance(node, ast.AnnAssign):
            return self._expr_to_str(node.value)
        if isinstance(node, ast.AugAssign):
            return self._expr_to_str(node.value)
        return ""

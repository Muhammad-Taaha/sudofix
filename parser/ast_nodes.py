from dataclasses import dataclass, field
from typing import List, Optional
from uuid import uuid4


@dataclass
class UnifiedNode:
    """
    Language-agnostic AST node used by parsers and SAST rules.

    Nodes are hierarchical: every node can hold children and a parent reference
    (via parent_id), allowing tree traversal in the scanner.
    """

    node_type: str
    name: Optional[str]
    code: str
    file_path: str
    start_line: int
    end_line: int
    language: str
    parent_id: Optional[str] = None
    children: List["UnifiedNode"] = field(default_factory=list)
    node_id: str = field(default_factory=lambda: str(uuid4()))

    def add_child(self, child: "UnifiedNode") -> None:
        """Attach a child node and set its parent_id."""
        child.parent_id = self.node_id
        self.children.append(child)

    def walk_depth_first(self) -> List["UnifiedNode"]:
        """
        Return this node and all descendants in depth-first pre-order.
        Useful for scanners that need to inspect every node.
        """
        result = [self]
        for child in self.children:
            result.extend(child.walk_depth_first())
        return result


@dataclass
class ModuleNode(UnifiedNode):
    """Root/module node for a source file."""

    def __init__(
        self,
        name: Optional[str],
        code: str,
        file_path: str,
        start_line: int,
        end_line: int,
        language: str,
    ):
        super().__init__(
            node_type="module",
            name=name,
            code=code,
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            language=language,
        )


@dataclass
class CallNode(UnifiedNode):
    """Represents a function/method call expression."""

    callee: str = ""
    arguments: List[str] = field(default_factory=list)

    def __init__(
        self,
        name: Optional[str],
        code: str,
        file_path: str,
        start_line: int,
        end_line: int,
        language: str,
        callee: str,
        arguments: Optional[List[str]] = None,
    ):
        super().__init__(
            node_type="call",
            name=name,
            code=code,
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            language=language,
        )
        self.callee = callee
        self.arguments = arguments or []


@dataclass
class AssignNode(UnifiedNode):
    """Represents an assignment statement."""

    targets: List[str] = field(default_factory=list)
    value: str = ""

    def __init__(
        self,
        name: Optional[str],
        code: str,
        file_path: str,
        start_line: int,
        end_line: int,
        language: str,
        targets: Optional[List[str]] = None,
        value: str = "",
    ):
        super().__init__(
            node_type="assignment",
            name=name,
            code=code,
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            language=language,
        )
        self.targets = targets or []
        self.value = value


@dataclass
class IfNode(UnifiedNode):
    """Represents an if/elif/else control-flow node."""

    condition: str = ""

    def __init__(
        self,
        name: Optional[str],
        code: str,
        file_path: str,
        start_line: int,
        end_line: int,
        language: str,
        condition: str = "",
    ):
        super().__init__(
            node_type="if",
            name=name,
            code=code,
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            language=language,
        )
        self.condition = condition


@dataclass
class LoopNode(UnifiedNode):
    """Represents for/while loop constructs."""

    loop_kind: str = ""
    condition: str = ""

    def __init__(
        self,
        name: Optional[str],
        code: str,
        file_path: str,
        start_line: int,
        end_line: int,
        language: str,
        loop_kind: str = "",
        condition: str = "",
    ):
        super().__init__(
            node_type="loop",
            name=name,
            code=code,
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            language=language,
        )
        self.loop_kind = loop_kind
        self.condition = condition


@dataclass
class ImportNode(UnifiedNode):
    """Represents an import statement."""

    module: str = ""
    alias: Optional[str] = None

    def __init__(
        self,
        name: Optional[str],
        code: str,
        file_path: str,
        start_line: int,
        end_line: int,
        language: str,
        module: str = "",
        alias: Optional[str] = None,
    ):
        super().__init__(
            node_type="import",
            name=name,
            code=code,
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            language=language,
        )
        self.module = module
        self.alias = alias


@dataclass
class ReturnNode(UnifiedNode):
    """Represents a return statement."""

    value: str = ""

    def __init__(
        self,
        name: Optional[str],
        code: str,
        file_path: str,
        start_line: int,
        end_line: int,
        language: str,
        value: str = "",
    ):
        super().__init__(
            node_type="return",
            name=name,
            code=code,
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            language=language,
        )
        self.value = value

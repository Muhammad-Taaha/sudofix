from dataclasses import dataclass

from typing import Optional, List


@dataclass
class UnifiedNode:

    node_type: str

    name: Optional[str]

    code: str

    file_path: str

    start_line: int

    end_line: int

    language: str

    # the node might have a parnt , might not have a parent
    parent_id: Optional[int] = None

    # the node might have a children , might not have a children
    children: Optional[List["UnifiedNode"]] = None


@dataclass
class CallNode:

    # this class represents how the function or the method is called  --

    callee: str

    arguments: List[str]


@dataclass
class ImportNode(UnifiedNode):
    """Represents an import statement."""

    alias: Optional[str] = None
    module: str = None

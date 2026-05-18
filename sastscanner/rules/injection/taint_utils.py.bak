import re
from typing import Dict, Iterable, Set

from parser.ast_nodes import AssignNode, UnifiedNode


IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# Very lightweight source indicators for user-controlled input.
TAINT_SOURCE_TOKENS = (
    "input(",
    "request.",
    "request[",
    "argv",
    "environ",
    "getenv(",
    "params",
    "query",
    "form",
    "json",
    "cookies",
    "headers",
    "body",
    "user_input",
)


def get_taint_state(context: Dict) -> Dict[str, bool]:
    """Get or initialize taint state on the shared scan context."""
    taint_state = context.get("taint_state")
    if not isinstance(taint_state, dict):
        taint_state = {}
        context["taint_state"] = taint_state
    return taint_state


def maybe_update_taint_from_node(ast_node: UnifiedNode, context: Dict) -> None:
    """Update taint state if this node is an assignment."""
    if not isinstance(ast_node, AssignNode) and ast_node.node_type != "assignment":
        return

    taint_state = get_taint_state(context)
    targets = getattr(ast_node, "targets", None) or []
    value = getattr(ast_node, "value", "") or ""
    if not targets:
        return

    tainted_value = is_user_controlled_expr(value) or any(
        taint_state.get(identifier, False) for identifier in extract_identifiers(value)
    )

    for target in targets:
        for identifier in extract_identifiers(target):
            # Keep only the direct variable taint (e.g. "cmd" from "cmd[0]" / "obj.cmd")
            taint_state[identifier] = tainted_value


def argument_looks_tainted(argument: str, context: Dict) -> bool:
    taint_state = get_taint_state(context)
    arg = (argument or "").strip()
    if not arg:
        return False
    if is_user_controlled_expr(arg):
        return True
    return any(taint_state.get(identifier, False) for identifier in extract_identifiers(arg))


def is_user_controlled_expr(expr: str) -> bool:
    lower = (expr or "").lower()
    return any(token in lower for token in TAINT_SOURCE_TOKENS)


def extract_identifiers(expr: str) -> Set[str]:
    """
    Extract likely variable names from expression text.
    Filters out common keywords/builtins to reduce noise.
    """
    if not expr:
        return set()
    keywords = {
        "true",
        "false",
        "none",
        "and",
        "or",
        "not",
        "if",
        "else",
        "for",
        "while",
        "in",
        "is",
        "return",
        "lambda",
    }
    identifiers = set(match.group(0) for match in IDENTIFIER_RE.finditer(expr))
    return {name for name in identifiers if name.lower() not in keywords}


def contains_concat_markers(expr: str) -> bool:
    lower = (expr or "").lower()
    return "+" in expr or ".format(" in lower or "%" in expr or ("{" in expr and "}" in expr)


def any_argument_tainted(arguments: Iterable[str], context: Dict) -> bool:
    return any(argument_looks_tainted(arg, context) for arg in arguments)

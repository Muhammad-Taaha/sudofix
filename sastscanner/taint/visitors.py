import re
from parser.ast_nodes import CallNode, AssignNode


class TaintVisitor:
    def __init__(self, state, rules, language: str):
        self.state = state
        self.rules = rules
        self.language = language

    def visit(self, node):
        node_type = getattr(node, "node_type", None)

        if node_type == "call":
            self.visit_CallNode(node)
        elif node_type == "assign":
            self.visit_AssignNode(node)

    def visit_CallNode(self, node):
        callee = getattr(node, "callee", "")
        if not callee:
            return

        # ----- 1. DIRECT SINK DETECTION (even without taint) -----
        if self.rules.is_sink(callee, self.language):
            # Immediate security issue – always report
            self.state.add_issue({
                "type": "taint",
                "sink": callee,
                "line": node.start_line,
                "code": node.code[:200],
                "language": self.language,
                "message": f"Dangerous function call: {callee}",
                "severity": "high"
            })
            # Also treat arguments as tainted (for propagation)
            args = getattr(node, "arguments", [])
            for arg in args:
                self._taint_vars_in_string(arg)

        # ----- 2. TAINT PROPAGATION -----
        # Check if callee is a source – mark its return value as tainted (handled in AssignNode)
        if self.rules.is_source(callee, self.language):
            # We'll rely on the AssignNode that captures the return value
            # For now, we can taint a special marker; but better to handle in AssignNode.
            pass

        # If any argument is tainted, raise a data‑flow issue
        args = getattr(node, "arguments", [])
        tainted_args = []
        for arg in args:
            if isinstance(arg, str):
                vars_in_arg = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', arg)
                for var in vars_in_arg:
                    if self.state.is_tainted(var):
                        tainted_args.append(var)
        if tainted_args:
            self.state.add_issue({
                "type": "taint_flow",
                "sink": callee,
                "line": node.start_line,
                "code": node.code[:200],
                "language": self.language,
                "tainted_arguments": tainted_args,
                "message": f"User‑controlled data reaches {callee} (tainted: {', '.join(tainted_args)})"
            })

    def visit_AssignNode(self, node):
        targets = getattr(node, "targets", [])
        value = getattr(node, "value", "")
        if not targets:
            return

        # Determine if RHS is tainted
        rhs_tainted = False

        # Check if RHS is a source call (e.g., input())
        if isinstance(value, str):
            if self.rules.is_source(value, self.language):
                rhs_tainted = True
            # Check for variables in RHS that are already tainted
            vars_in_rhs = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', value)
            for var in vars_in_rhs:
                if self.state.is_tainted(var):
                    rhs_tainted = True
                    break

        if rhs_tainted:
            for target in targets:
                if isinstance(target, str):
                    self.state.taint_var(target)
                else:
                    # Extract variable names from compound targets (tuples, lists)
                    names = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', str(target))
                    for name in names:
                        self.state.taint_var(name)

    def _taint_vars_in_string(self, s: str):
        if not isinstance(s, str):
            return
        vars_in = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', s)
        for var in vars_in:
            self.state.taint_var(var)
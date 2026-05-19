import re


class TaintVisitor:
    def __init__(self, state, rules, language: str, nodes: list = None):
        self.state = state
        self.rules = rules
        self.language = language
        self.nodes = nodes or []

    def visit(self, node):
        node_type = getattr(node, "node_type", None)

        if node_type == "call":
            self.visit_CallNode(node)

        elif node_type == "assignment":
            self.visit_AssignNode(node)

        elif node_type == "return":
            self.visit_ReturnNode(node)

    # =========================
    # CALL NODE
    # =========================
    def visit_CallNode(self, node):
        callee = getattr(node, "callee", "")
        args = getattr(node, "arguments", [])

        if not callee:
            return

        # -------------------------
        # SANITIZER (CALL-BASED)
        # -------------------------
        if self.rules.is_sanitizer(callee, self.language):
            for arg in args:
                for var in re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", str(arg)):
                    self.state.sanitize_var(var, callee)

        # -------------------------
        # SINK CHECK
        # -------------------------
        if self.rules.is_sink(callee, self.language):

            for arg in args:
                for var in re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", str(arg)):

                    info = self.state.get_var_info(var)

                    if not info:
                        continue

                    if not info.get("tainted", False):
                        continue

                    if info.get("sanitized", False):
                        continue

                    self.state.add_issue(
                        {
                            "type": "taint",
                            "sink": callee,
                            "line": node.start_line,
                            "code": node.code[:200],
                            "language": self.language,
                            "message": f"Tainted data reaches sink: {callee}",
                            "severity": "HIGH",
                        }
                    )

        # -------------------------
        # FLOW TRACKING
        # -------------------------
        tainted_args = []

        for arg in args:
            for var in re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", str(arg)):
                if self.state.is_tainted(var):
                    tainted_args.append(var)

        if tainted_args:
            self.state.add_issue(
                {
                    "type": "taint_flow",
                    "sink": callee,
                    "line": node.start_line,
                    "code": node.code[:200],
                    "language": self.language,
                    "tainted_arguments": tainted_args,
                    "message": f"Tainted flow into {callee}",
                    "severity": "LOW",
                }
            )

    # =========================
    # ASSIGN NODE (FIXED SANITIZATION HANDLING)
    # =========================
    def visit_AssignNode(self, node):
        targets = getattr(node, "targets", [])
        value = getattr(node, "value", "")

        if not targets:
            return

        value_str = str(value)

        # -------------------------
        # 🔥 FIX 1: SANITIZER IN ASSIGNMENT
        # x = html.escape(x)
        # -------------------------
        if self.rules.is_sanitizer(value_str, self.language):
            for target in targets:
                if isinstance(target, str):
                    self.state.sanitize_var(target, value_str)
            return

        rhs_tainted = False
        source_var = None

        if isinstance(value, str):

            if self.rules.is_source(value, self.language):
                rhs_tainted = True

            for var in re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", value):
                if self.state.is_tainted(var):
                    rhs_tainted = True
                    source_var = var
                    break

        if rhs_tainted:

            for target in targets:
                if isinstance(target, str):

                    # -------------------------
                    # FIX 2: PROPER PROPAGATION
                    # -------------------------
                    if source_var:
                        self.state.propagate(source_var, target)
                    else:
                        self.state.taint_var(target)

                else:
                    for name in re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", str(target)):
                        self.state.taint_var(name)
        else:
            # If the RHS is completely safe, untaint the targets (Fixing Re-assignment Bug)
            for target in targets:
                if isinstance(target, str):
                    self.state.untaint_var(target)
                else:
                    for name in re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", str(target)):
                        self.state.untaint_var(name)

    # =========================
    # RETURN NODE (RETURN TAINT PROPAGATION)
    # =========================
    def visit_ReturnNode(self, node):
        value = getattr(node, "value", "")
        if not value:
            return

        is_tainted_return = False
        if self.rules.is_source(value, self.language):
            is_tainted_return = True
        else:
            for var in re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", value):
                if self.state.is_tainted(var):
                    is_tainted_return = True
                    break

        if is_tainted_return:
            func_name = self._get_enclosing_function_name(node.start_line)
            if func_name:
                # Dynamically register the local function as a taint source!
                pattern = rf"\b{re.escape(func_name)}\s*\("
                if self.language in self.rules.sources:
                    if pattern not in self.rules.sources[self.language]:
                        self.rules.sources[self.language].append(pattern)

    def _get_enclosing_function_name(self, line: int) -> str:
        for node in getattr(self, "nodes", []):
            if getattr(node, "node_type", None) == "function":
                start = getattr(node, "start_line", 0)
                end = getattr(node, "end_line", 0)
                if start <= line <= end:
                    return getattr(node, "name", "")
        return ""

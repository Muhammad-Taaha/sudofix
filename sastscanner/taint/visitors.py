from parser.ast_nodes import CallNode, AssignNode


class TaintVisitor:
    def __init__(self, state, rules, lang):
        self.state = state
        self.rules = rules
        self.lang = lang
        self.vulnerabilities = []

    def visit(self, node):
        if not node:
            return

        node_type = getattr(node, "type", None)
        if not node_type:
            return

        method = f"visit_{node_type.lower()}"
        visitor = getattr(self, method, self.generic_visit)
        visitor(node)
    def generic_visit(self, node):
        for child in getattr(node, "children", []):
            self.visit(child)

    # ==============================
    # ASSIGNMENT TRACKING
    # ==============================
    def visit_AssignNode(self, node: AssignNode):
        target = getattr(node, "target", None)
        value = getattr(node, "value", None)

        # Case: x = input()
        if isinstance(value, CallNode):
            if self.rules.is_source(value.name, self.lang):
                self.state.taint(target)

        # Case: x = y
        elif isinstance(value, str):
            if self.state.is_tainted(value):
                self.state.taint(target)

        self.generic_visit(node)

    # ==============================
    # FUNCTION CALL TRACKING
    # ==============================
    def visit_CallNode(self, node: CallNode):
        func_name = node.name

        # 🚨 Check sink
        if self.rules.is_sink(func_name, self.lang):
            for arg in node.args:
                if isinstance(arg, str) and self.state.is_tainted(arg):
                    self.vulnerabilities.append({
                        "type": "TAINT_FLOW",
                        "message": f"Tainted data passed to sink: {func_name}",
                        "node": node
                    })

        # Track propagation via function args
        for arg in node.args:
            if isinstance(arg, str) and self.state.is_tainted(arg):
                # Example: dangerous_func(x) → mark return or effect
                pass

        self.generic_visit(node)
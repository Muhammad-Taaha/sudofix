# Covers:
# - Sources
# - Propagation
# - Sinks
# - Sanitization
# - String/Binary ops

from typing import Dict, List


class TaintEngine:
    def __init__(self):
        self.tainted_vars: Dict[str, bool] = {}
        self.vulnerabilities: List[Dict] = []

        # ----------------------
        # SOURCES
        # ----------------------
        self.SOURCES = {
            "input",
            "request.GET",
            "request.POST",
            "sys.argv",
        }

        # ----------------------
        # SINK RULES
        # ----------------------
        self.SINK_RULES = {
            "execute": {"type": "SQL Injection", "severity": "HIGH"},
            "system": {"type": "Command Injection", "severity": "CRITICAL"},
            "popen": {"type": "Command Injection", "severity": "CRITICAL"},
            "open": {"type": "Path Traversal", "severity": "HIGH"},
        }

        # ----------------------
        # SANITIZERS
        # ----------------------
        self.SANITIZERS = {"int", "float", "escape"}

    # ==============================
    # ENTRY POINT
    # ==============================
    def analyze(self, nodes: List):
        for node in nodes:
            self._visit(node)
        return self.vulnerabilities

    # ==============================
    # DISPATCHER
    # ==============================
    def _visit(self, node):
        method = f"visit_{node.type.lower()}"
        visitor = getattr(self, method, self.generic_visit)
        visitor(node)

    def generic_visit(self, node):
        for child in getattr(node, "children", []):
            self._visit(child)

    # ==============================
    # ASSIGNMENT HANDLING
    # ==============================
    def visit_assign(self, node):
        target = node.target
        value = node.value

        if self._is_source(value):
            self.tainted_vars[target] = True

        elif self._is_sanitized(value):
            self.tainted_vars[target] = False

        elif self._is_tainted(value):
            self.tainted_vars[target] = True

        else:
            self.tainted_vars[target] = False

        self.generic_visit(node)

    # ==============================
    # FUNCTION CALL (SINK DETECTION)
    # ==============================
    def visit_call(self, node):
        func_name = node.func_name
        args = node.args

        if func_name in self.SINK_RULES:
            for arg in args:
                if self._is_tainted(arg):
                    self._report_vulnerability(node, func_name)

        self.generic_visit(node)

    # ==============================
    # SOURCE DETECTION
    # ==============================
    def _is_source(self, node):
        if hasattr(node, "func_name"):
            return node.func_name in self.SOURCES
        if hasattr(node, "value"):
            return node.value in self.SOURCES
        return False

    # ==============================
    # SANITIZATION
    # ==============================
    def _is_sanitized(self, node):
        if hasattr(node, "func_name"):
            return node.func_name in self.SANITIZERS
        return False

    # ==============================
    # TAINT CHECK (CORE LOGIC)
    # ==============================
    def _is_tainted(self, node):
        # Variable
        if hasattr(node, "name"):
            return self.tainted_vars.get(node.name, False)

        # Direct source
        if self._is_source(node):
            return True

        # Function call propagation
        if hasattr(node, "args"):
            return any(self._is_tainted(arg) for arg in node.args)

        # Binary operations (string concat etc.)
        if node.type == "BinaryOp":
            return self._handle_binary_op(node)

        return False

    # ==============================
    # HANDLE STRING CONCAT / OPS
    # ==============================
    def _handle_binary_op(self, node):
        left = node.left
        right = node.right
        return self._is_tainted(left) or self._is_tainted(right)

    # ==============================
    # REPORTING
    # ==============================
    def _report_vulnerability(self, node, sink):
        rule = self.SINK_RULES[sink]

        self.vulnerabilities.append({
            "type": rule["type"],
            "severity": rule["severity"],
            "sink": sink,
            "line": getattr(node, "line", None),
            "message": f"Tainted data passed to {sink}"
        })



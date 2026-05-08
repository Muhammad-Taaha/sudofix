from typing import List
from .taint_state import TaintState
from .taint_rules import TaintRules
from .visitors import TaintVisitor


class TaintEngine:
    def __init__(self, language: str = "python"):
        self.language = language
        self.rules = TaintRules()

        # proper state object
        self.state = TaintState()

        # visitor gets engine reference
        self.visitor = TaintVisitor(self.state, self.rules, self.language)

    # ==============================
    # ENTRY POINT
    # ==============================
    def analyze(self, nodes: List, language: str = "generic"):
        self.state.reset()

        if not nodes:
            return []

        for node in nodes:
            if node is None:
                continue

            try:
                self.visitor.visit(node)
            except Exception:
                continue

        return self.state.issues
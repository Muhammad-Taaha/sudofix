from typing import List
from .taint_state import TaintState
from .taint_rules import TaintRules
from .visitors import TaintVisitor


class TaintEngine:
    def __init__(self, language: str = "python"):
        self.language = language
        self.rules = TaintRules()
        self.state = TaintState()

    def analyze(self, nodes: List, language: str = "generic") -> List:
        lang = language if language != "generic" else self.language
        visitor = TaintVisitor(self.state, self.rules, lang)
        self.state.reset()

        for node in nodes:
            if node is None:
                continue
            try:
                visitor.visit(node)
            except Exception:
                continue

        return self.state.issues
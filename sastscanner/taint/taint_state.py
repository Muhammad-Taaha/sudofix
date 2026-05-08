class TaintState:
    def __init__(self):
        self.tainted_vars = set()
        self.issues = []   # ✅ ADD THIS

    def taint(self, var: str):
        self.tainted_vars.add(var)

    def is_tainted(self, var: str) -> bool:
        return var in self.tainted_vars 

    def add_issue(self, issue: dict):
        self.issues.append(issue)

    def reset(self):
        self.tainted_vars.clear()
        self.issues.clear()

    def __len__(self):
        return len(self.issues)   # ✅ NOW VALID
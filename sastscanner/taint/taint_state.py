class TaintState:
    def __init__(self):
        self.tainted_vars = {}
        self.issues = []

    # =========================
    # TAINT
    # =========================
    def taint_var(self, var: str, source: str = "unknown"):
        if not var:
            return

        self.tainted_vars[var] = {
            "tainted": True,
            "source": source,
            "sanitized": False,
            "sanitizers": [],
        }

    def untaint_var(self, var: str):
        self.tainted_vars.pop(var, None)

    # =========================
    # SANITIZE
    # =========================
    def sanitize_var(self, var: str, sanitizer: str):
        if var in self.tainted_vars:
            self.tainted_vars[var]["sanitized"] = True
            self.tainted_vars[var]["tainted"] = False  # IMPORTANT FIX
            self.tainted_vars[var]["sanitizers"].append(sanitizer)

    # =========================
    # CHECKS
    # =========================
    def is_tainted(self, var: str) -> bool:
        return self.tainted_vars.get(var, {}).get("tainted", False)

    def get_var_info(self, var: str):
        return self.tainted_vars.get(var)

    # =========================
    # PROPAGATION
    # =========================
    def propagate(self, src: str, dest: str):
        if src in self.tainted_vars:
            self.tainted_vars[dest] = self.tainted_vars[src].copy()

    # =========================
    # ISSUES
    # =========================
    def add_issue(self, issue: dict):
        issue.setdefault("severity", "LOW")
        issue.setdefault("confidence", "MEDIUM")
        self.issues.append(issue)

    def reset(self):
        self.tainted_vars.clear()
        self.issues.clear()

    def __len__(self):
        return len(self.issues)

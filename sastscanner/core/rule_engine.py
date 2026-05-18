import importlib
import pkgutil
from typing import List, Dict, Any

from sastscanner.findings.finding import Finding
from sastscanner.rules.base_rule import BaseRule


class RuleEngine:

    def __init__(self, rules_package: str = "sastscanner.rules"):
        self.rules: List[BaseRule] = []
        self._load_rules_recursive(rules_package)
        print(f"[RuleEngine] Loaded {len(self.rules)} rules:")
        for r in self.rules:
            print(f"  - {r.name}")

    def _load_rules_recursive(self, package_name: str):
        """Recursively import all submodules of a package and collect rule classes."""
        try:
            package = importlib.import_module(package_name)
        except ImportError:
            return

        # Modules directly in this package
        for _, module_name, is_pkg in pkgutil.iter_modules(package.__path__):
            full_module_name = f"{package_name}.{module_name}"
            if is_pkg:
                # Recurse into subpackage
                self._load_rules_recursive(full_module_name)
            else:
                # Import the module and collect rule classes
                try:
                    module = importlib.import_module(full_module_name)
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if (isinstance(attr, type) and
                            issubclass(attr, BaseRule) and
                            attr != BaseRule):
                            self.rules.append(attr())
                except Exception as e:
                    print(f"⚠️ Failed to load rule from {full_module_name}: {e}")

    def scan(self, chunk: Dict[str, Any], context: Dict[str, Any] = None) -> List[Finding]:
        context = context or {}
        taint_findings = chunk.get("taint_findings", [])
        context["taint_findings"] = taint_findings

        findings = []
        for rule in self.rules:
            try:
                findings.extend(rule.check(chunk, context))
            except Exception as e:
                print(f"⚠️ Rule {rule.name} failed: {e}")
        return findings
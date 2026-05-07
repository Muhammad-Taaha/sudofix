import importlib
import pkgutil
from typing import List, Dict, Any

from findings.finding import Finding
from rules.base_rule import BaseRule


class RuleEngine:

    def __init__(self, rules_package: str = "sastscanner.rules"):
        self.rules: List[BaseRule] = []
        self._load_rules(rules_package)

    def _load_rules(self, package_name: str):
        """Auto-discover all rule classes in the given package."""
        package = importlib.import_module(package_name)

        for _, module_name, _ in pkgutil.iter_modules(package.__path__):
            module = importlib.import_module(f"{package_name}.{module_name}")

            for attr_name in dir(module):
                attr = getattr(module, attr_name)

                if (
                    isinstance(attr, type)
                    and issubclass(attr, BaseRule)
                    and attr != BaseRule
                ):
                    self.rules.append(attr())

    def scan(self, chunk: Dict[str, Any], context: Dict[str, Any] = None) -> List[Finding]:
        """
        Run all rules on a single chunk.
        Now taint-aware.
        """
        context = context or {}
        findings = []

        # 🔥 IMPORTANT: extract taint info
        taint_findings = chunk.get("taint_findings", [])

        context["taint_findings"] = taint_findings

        for rule in self.rules:
            try:
                findings.extend(rule.check(chunk, context))
            except Exception as e:
                print(f"⚠️ Rule {rule.name} failed: {e}")

        return findings
import importlib
import pkgutil
from typing import Any, Dict, List

from ..findings.finding import Finding
from ..rules.base_rule import BaseRule


class RuleRunner:
    def __init__(self, rules_package: str = "sastscanner.rules"):
        self.rules: List[BaseRule] = []
        self._load_rules_recursive(rules_package)

    def _load_rules_recursive(self, package_name: str):
        """Recursively import all modules under package_name and collect rule classes."""
        try:
            package = importlib.import_module(package_name)
        except ImportError as e:
            print(f"⚠️ Could not import package {package_name}: {e}")
            return

        # Walk through all modules and subpackages
        for _, module_name, is_pkg in pkgutil.walk_packages(
            package.__path__, prefix=package_name + "."
        ):
            if is_pkg:
                # Recursively load subpackage (already covered by walk_packages)
                continue
            try:
                module = importlib.import_module(module_name)
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, BaseRule)
                        and attr != BaseRule
                    ):
                        self.rules.append(attr())
            except Exception as e:
                print(f"⚠️ Failed to load rule from {module_name}: {e}")

    def run(
        self, node: Dict[str, Any], context: Dict[str, Any] = None
    ) -> List[Finding]:
        context = context or {}
        findings = []
        for rule in self.rules:
            try:
                findings.extend(rule.check(node, context))
            except Exception as e:
                print(f"⚠️ Rule {rule.name} failed: {e}")
        return findings

import importlib

import pkgutil

from typing import List, Dict, Any

from ..findings.finding import Finding

from ..rules.base_rule import BaseRule


class RuleRunner:

    def __init__(self, rules_package: str = "sastscanner.rules"):
        self.rules: List[BaseRule] = []

        self._load_rules(rules_package)

    def _load_rules(self, package_name: str):
        try:
            package = importlib.import_module(package_name)
            for _, module_name, _ in pkgutil.iter_modules(package.__path__):
                module = importlib.import_module(
                    f"{package_name}.{module_name}")
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, BaseRule)
                        and attr != BaseRule
                    ):
                        self.rules.append(attr())
        except Exception as e:
            print(f"⚠️ Failed to load rules from {package_name}: {e}")

    def run(
        self, node: Dict[str, Any], context: Dict[str, Any] = None
    ) -> List[Finding]:
        context = context or {}
        all_findings = []
        for rule in self.rules:
            try:
                findings = rule.check(node, context)
                all_findings.extend(findings)
            except Exception as e:
                print(f"⚠️ Rule {rule.name} failed: {e}")
        return all_findings

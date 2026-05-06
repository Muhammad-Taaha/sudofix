#!/usr/bin/env python3
import sys
from pathlib import Path

# Add repo root to path
repo_root = Path(__file__).parent.parent
sys.path.insert(0, str(repo_root))

from sastscanner.core.orchestrator import Orchestrator
from sastscanner.core.rule_runner import RuleRunner

print(f"Loaded rules: {[r.name for r in RuleRunner().rules]}")

BASE_TESTS = Path(__file__).parent / "test_cases_for_sast" / "injection"

EXPECTED_RULES = {
    "command_injection": {
        "vulnerable.py": "Command Injection",
        "safe.py": None,
    },
    "command_subprocess": {
        "vulnerable.py": "Command Injection",
        "safe.py": None,
    },
    "sql_concat": {
        "vulnerable.py": "SQL Injection via String Concatenation",
        "safe.py": None,
    },
    "sql_orm_raw": {
        "vulnerable.py": "ORM Raw SQL Execution",
        "safe.py": None,
    },
    "code_eval": {
        "vulnerable.py": "Dynamic Code Execution (eval/exec)",
        "safe.py": None,
    },
    "ldap_injection": {
        "vulnerable.py": "LDAP Injection",
        "safe.py": None,
    },
    "nosql_mongo": {
        "vulnerable.js": "NoSQL Injection (MongoDB)",
        "safe.js": None,
    },
    "template_engine": {
        "vulnerable.py": "Server‑Side Template Injection",
        "safe.py": None,
    }
}

def run_test(test_dir: Path, filename: str, expected_rule: str | None):
    file_path = test_dir / filename
    if not file_path.exists():
        print(f"❌ Missing: {file_path}")
        return False

    print(f"\n🔍 Scanning: {file_path}")
    orchestrator = Orchestrator(str(test_dir))
    try:
        findings = orchestrator.scan_file(str(file_path))
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

    rule_names = [f.rule_name for f in findings]
    if expected_rule is None:
        if not rule_names:
            print(f"   ✅ Safe – no findings (as expected)")
            return True
        else:
            print(f"   ❌ Safe triggered: {rule_names}")
            return False
    else:
        if expected_rule in rule_names:
            print(f"   ✅ Vulnerable – found '{expected_rule}'")
            return True
        else:
            print(f"   ❌ Expected '{expected_rule}' but got {rule_names}")
            return False

def main():
    if not BASE_TESTS.exists():
        print(f"❌ Test base directory not found: {BASE_TESTS}")
        print("   Run generate_test_cases.py first.")
        sys.exit(1)

    passed = total = 0
    for rule_dir, files in EXPECTED_RULES.items():
        test_path = BASE_TESTS / rule_dir
        if not test_path.exists():
            print(f"⚠️ Skipping {rule_dir} – missing")
            continue
        for filename, expected in files.items():
            total += 1
            if run_test(test_path, filename, expected):
                passed += 1

    print(f"\n{'='*50}")
    print(f"Results: {passed}/{total} tests passed")
    sys.exit(0 if passed == total else 1)

if __name__ == "__main__":
    main()
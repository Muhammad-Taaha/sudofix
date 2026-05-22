import shutil
import pytest
from pathlib import Path
from sca.rule_scanner import RuleScanner, HAS_AST_GREP
from sca.scanners import VendoredScanner

@pytest.mark.skipif(not HAS_AST_GREP, reason="ast-grep-py not installed")
def test_eval_detection(tmp_path):
    file = tmp_path / "test.py"
    file.write_text("x = eval('2+2')\n")
    scanner = RuleScanner()
    findings = scanner.scan_files([file])
    assert len(findings) >= 1
    assert findings[0].rule_id == "python-eval"
    assert findings[0].severity == "high"

@pytest.mark.skipif(shutil.which("scancode") is None, reason="scancode not available")
def test_vendored_detects_package_json(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "package.json").write_text('{"name": "test", "version": "1.0.0"}')
    scanner = VendoredScanner()
    matches = scanner.scan_directory(str(project))
    assert any(m.package_name == "test" for m in matches)
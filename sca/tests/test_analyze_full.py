from sca import analyze
import sca.rule_scanner as rule_scanner
import pytest
import textwrap


def _write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content))


def test_analyze_full_stack(tmp_path):
    """Create a project with several manifests, source files and metadata
    in a temp directory and ensure `analyze` returns a complete result.
    """
    project = tmp_path / "full_project"
    project.mkdir()

    # npm
    _write(project / "package.json", """
    {"name": "test", "dependencies": {"chalk": "^5.0.0"}}
    """)
    _write(project / "package-lock.json", """
    {"lockfileVersion": 2, "packages": {"": {"name": "test", "dependencies": {"chalk": "^5.0.0"}}, "node_modules/chalk": {"version": "5.3.0"}}}
    """)

    # pypi
    _write(project / "requirements.txt", """
    requests==2.31.0
    """)

    # maven
    _write(project / "pom.xml", """
    <project xmlns="http://maven.apache.org/POM/4.0.0">
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>demo</artifactId>
      <version>1.0.0</version>
    </project>
    """)

    # go
    _write(project / "go.mod", """
    module example.com/test

    require github.com/stretchr/testify v1.7.0
    """)

    # simple python source to exercise import mapping
    _write(project / "src" / "main.py", """
    import os
    import requests
    """)

    # license file (simple copyright line to be picked up as candidate)
    _write(project / "LICENSE", """
    Copyright (c) 2024 Example
    MIT License
    """)

    # vendor-like directory (scanner may or may not detect it depending on scancode presence)
    _write(project / "vendor" / "vendored.c", """
    /* vendored code */
    """)

    result = analyze(str(project))
    assert result["status"] == "ok"
    assert "sub_projects" in result
    assert isinstance(result["sub_projects"], list)
    assert len(result["sub_projects"]) == 1

    sub = result["sub_projects"][0]
    # Basic shape checks
    for k in ("packages", "imports", "license_findings", "vendored_matches", "rule_findings", "vulnerabilities", "outdated"):
        assert k in sub

    assert isinstance(sub["packages"], list)
    assert isinstance(sub["imports"], dict)

    # Ensure import mapping picked up 'requests'
    assert any(k == "requests" for k in sub["imports"].keys())

    # License findings may be empty if scancode not available; if present, ensure file paths include LICENSE
    if sub["license_findings"]:
        assert any("LICENSE" in f.get("file_path", "") or "license" in f.get("file_path", "").lower() for f in sub["license_findings"])


def test_analyze_subprojects_and_flag(tmp_path):
    """Create a root with two subprojects and validate monorepo detection
    and the `no_subprojects` override.
    """
    root = tmp_path / "mono"
    root.mkdir()

    sub1 = root / "sub1"
    sub2 = root / "sub2"
    sub1.mkdir()
    sub2.mkdir()

    _write(sub1 / "package.json", '{"name": "s1", "dependencies": {}}')
    _write(sub2 / "requirements.txt", 'requests==2.31.0')

    # Without override, should detect both subprojects
    result = analyze(str(root))
    assert result["status"] == "ok"
    assert len(result["sub_projects"]) >= 2

    # With override, only root should be analyzed
    result2 = analyze(str(root), no_subprojects=True)
    assert result2["status"] == "ok"
    assert len(result2["sub_projects"]) == 1


def test_rule_scanner_detects_eval_if_available(tmp_path):
    """If `ast-grep-py` is installed, the rule scanner should detect `eval()` usage
    according to the included `python-eval` rule.
    """
    if not rule_scanner.HAS_AST_GREP:
        pytest.skip("ast-grep-py not installed; skipping rule scanner integration test")

    project = tmp_path / "rules_project"
    project.mkdir()
    _write(project / "bad.py", """
    user_input = '1+1'
    eval(user_input)
    """)

    result = analyze(str(project))
    assert result["status"] == "ok"
    sub = result["sub_projects"][0]
    # Expect at least one rule finding containing the python-eval id
    assert any(f.get("rule_id") == "python-eval" for f in sub.get("rule_findings", []))

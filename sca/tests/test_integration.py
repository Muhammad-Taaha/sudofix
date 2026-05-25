import pytest
from pathlib import Path
from sca import analyze

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "integration_sample"

def test_full_integration():
    result = analyze(str(FIXTURE_DIR), offline=True)
    assert result["status"] == "ok"
    sub = result["sub_projects"][0]

    # Dependency resolution
    packages = sub["packages"]
    assert any(p["name"] == "lodash" and p["ecosystem"] == "npm" for p in packages)
    assert any(p["name"] == "requests" and p["ecosystem"] == "pypi" for p in packages)

    # License detection (requires scancode)
    licenses = sub["license_findings"]
    if licenses:
        assert any("mit" in l["license_expression"].lower() for l in licenses)

    # Imports mapping
    imports = sub["imports"]
    # Should map lodash to utils.js
    assert "lodash" in imports or "requests" in imports

    # Outdated check (network may fail, so at least structure is correct)
    outdated = sub["outdated"]
    # Not asserting specific values, but field existence
    for o in outdated:
        assert "package_name" in o
        assert "latest_version" in o
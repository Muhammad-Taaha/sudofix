from sca.vex import generate_vex
from sca.vulnerability_mapper import VulnerabilityFinding
import json

def test_generate_vex():
    findings = [
        VulnerabilityFinding(
            vulnerability_id="CVE-2023-12345",
            severity="HIGH",
            package_name="lodash",
            package_version="4.17.15",
            ecosystem="npm",
            exploitability="reachable",
        )
    ]
    vex_json = generate_vex(findings)
    data = json.loads(vex_json)
    assert data["statements"][0]["status"] == "affected"

def test_generate_vex_not_reachable():
    findings = [
        VulnerabilityFinding(
            vulnerability_id="CVE-2023-12346",
            severity="MEDIUM",
            package_name="express",
            package_version="4.18.0",
            ecosystem="npm",
            exploitability="not_reachable",
        )
    ]
    vex_json = generate_vex(findings)
    data = json.loads(vex_json)
    assert data["statements"][0]["status"] == "not_affected"
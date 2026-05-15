"""Minimal VEX (Vulnerability Exploitability eXchange) generator."""

from __future__ import annotations

import json
from typing import List
from sca.vulnerability_mapper import VulnerabilityFinding


def generate_vex(findings: List[VulnerabilityFinding], author: str = "sca-tool") -> str:
    """
    Generate a VEX JSON document from a list of VulnerabilityFindings.
    Each finding is marked as 'affected' if exploitability == 'reachable',
    'not_affected' if exploitability == 'not_reachable',
    and 'under_investigation' otherwise.
    """
    vex = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://sca.example.com/vex/1",
        "author": author,
        "role": "Document Creator",
        "timestamp": "",
        "version": 1,
        "statements": []
    }

    for f in findings:
        if f.exploitability == "reachable":
            status = "affected"
        elif f.exploitability == "not_reachable":
            status = "not_affected"
        else:
            status = "under_investigation"

        statement = {
            "vulnerability": {
                "name": f.vulnerability_id,
                "description": f.description,
            },
            "products": [
                {
                    "@id": f"pkg:{f.ecosystem}/{f.package_name}@{f.package_version}",
                    "name": f.package_name,
                    "version": f.package_version,
                }
            ],
            "status": status,
        }
        if f.file_path:
            statement["products"][0]["file"] = f.file_path
        vex["statements"].append(statement)

    return json.dumps(vex, indent=2)
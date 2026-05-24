import json
from pathlib import Path
from sca.resolver.plugins.swift import SwiftResolver

def test_swift_resolver(tmp_path):
    project = tmp_path / "swift_app"
    project.mkdir()
    resolved = {
        "pins": [
            {"identity": "Alamofire", "state": {"version": "5.6.4"}},
            {"identity": "SwiftyJSON", "state": {"version": "5.0.1"}}
        ]
    }
    (project / "Package.resolved").write_text(json.dumps(resolved))
    resolver = SwiftResolver()
    packages = resolver.resolve(str(project))
    assert len(packages) == 2
    names = {p.name for p in packages}
    assert names == {"Alamofire", "SwiftyJSON"}
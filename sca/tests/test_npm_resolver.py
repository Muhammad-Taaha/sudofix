import json
from pathlib import Path
from sca.resolver.plugins.npm import NpmResolver


def test_npm_resolver_package_lock(tmp_path):
    # Create a minimal npm project inside the temp directory
    project = tmp_path / "sample"
    project.mkdir()

    # package.json
    package_json = {
        "name": "sample-project",
        "dependencies": {
            "lodash": "^4.17.21",
            "express": "^4.18.0"
        }
    }
    (project / "package.json").write_text(json.dumps(package_json))

    # package-lock.json (v2)
    lock_data = {
        "lockfileVersion": 2,
        "packages": {
            "": {
                "name": "sample-project",
                "dependencies": {
                    "lodash": "^4.17.21",
                    "express": "^4.18.0"
                }
            },
            "node_modules/lodash": {
                "version": "4.17.21"
            },
            "node_modules/express": {
                "version": "4.18.2",
                "dependencies": {
                    "accepts": "~1.3.8",
                    "array-flatten": "1.1.1"
                }
            },
            "node_modules/accepts": {
                "version": "1.3.8",
                "dependencies": {
                    "mime-types": "~2.1.34"
                }
            },
            "node_modules/array-flatten": {
                "version": "1.1.1"
            },
            "node_modules/mime-types": {
                "version": "2.1.35"
            }
        }
    }
    (project / "package-lock.json").write_text(json.dumps(lock_data))

    resolver = NpmResolver()
    packages = resolver.resolve(str(project))

    # We expect 5 packages: lodash, express, accepts, array-flatten, mime-types
    assert len(packages) == 5

    # Spot-check a few
    lodash = next(p for p in packages if p.name == "lodash")
    assert lodash.version == "4.17.21"
    assert lodash.is_direct  # because lodash is a direct dependency in package.json

    express = next(p for p in packages if p.name == "express")
    assert express.is_direct
    assert "accepts" in express.dependencies
import json
from pathlib import Path
import toml
import pytest
from sca.resolver.plugins.pypi import PypiResolver


def test_poetry_lock(tmp_path):
    project = tmp_path / "poetry_proj"
    project.mkdir()
    lock_data = {
        "package": [
            {
                "name": "requests",
                "version": "2.31.0",
                "dependencies": {"certifi": ">=2017.4.17", "charset-normalizer": ">=2,<4"}
            },
            {
                "name": "certifi",
                "version": "2023.7.22",
                "dependencies": {}
            }
        ]
    }
    (project / "poetry.lock").write_text(toml.dumps(lock_data))
    # Add a pyproject.toml for direct deps detection
    pyproject = {
        "tool": {
            "poetry": {
                "name": "test",
                "version": "0.1",
                "dependencies": {"requests": "^2.31"}
            }
        }
    }
    (project / "pyproject.toml").write_text(toml.dumps(pyproject))

    resolver = PypiResolver()
    packages = resolver.resolve(str(project))
    assert len(packages) == 2
    requests_pkg = next(p for p in packages if p.name == "requests")
    assert requests_pkg.version == "2.31.0"
    assert requests_pkg.is_direct
    assert "certifi" in requests_pkg.dependencies


def test_requirements_txt(tmp_path):
    project = tmp_path / "req_proj"
    project.mkdir()
    (project / "requirements.txt").write_text("flask==2.3.3\nclick>=8.0\n")
    resolver = PypiResolver()
    packages = resolver.resolve(str(project))
    assert len(packages) >= 2
    flask = next(p for p in packages if p.name == "flask")
    assert flask.version == "2.3.3"
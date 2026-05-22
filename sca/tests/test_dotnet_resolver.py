import pytest
from pathlib import Path
from sca.resolver.plugins.dotnet import DotnetResolver

PACKAGES_CONFIG = """<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="13.0.1" targetFramework="net48" />
  <package id="Serilog" version="2.10.0" targetFramework="net48" />
  <package id="EntityFramework" version="6.4.4" targetFramework="net48" />
</packages>
"""

def test_resolves_all_packages():
    project = Path("/tmp/dotnet")
    project.mkdir(parents=True, exist_ok=True)
    (project / "packages.config").write_text(PACKAGES_CONFIG)
    resolver = DotnetResolver()
    packages = resolver.resolve(str(project))
    assert len(packages) == 3
    names = {p.name for p in packages}
    assert names == {"Newtonsoft.Json", "Serilog", "EntityFramework"}

def test_version_extraction():
    project = Path("/tmp/dotnet2")
    project.mkdir(parents=True, exist_ok=True)
    (project / "packages.config").write_text(PACKAGES_CONFIG)
    resolver = DotnetResolver()
    packages = resolver.resolve(str(project))
    newton = next(p for p in packages if p.name == "Newtonsoft.Json")
    assert newton.version == "13.0.1"

def test_no_packages_config_empty():
    project = Path("/tmp/empty_dotnet")
    project.mkdir(parents=True, exist_ok=True)
    resolver = DotnetResolver()
    assert resolver.resolve(str(project)) == []

def test_can_handle():
    resolver = DotnetResolver()
    assert resolver.can_handle(["some/path/packages.config"])
    assert not resolver.can_handle(["package.json"])

def test_malformed_xml_graceful():
    project = Path("/tmp/broken")
    project.mkdir(parents=True, exist_ok=True)
    (project / "packages.config").write_text("this is not XML")
    resolver = DotnetResolver()
    packages = resolver.resolve(str(project))
    assert packages == []  # should not crash

def test_nested_packages_config():
    project = Path("/tmp/nested")
    subdir = project / "sub"
    subdir.mkdir(parents=True, exist_ok=True)
    (subdir / "packages.config").write_text(PACKAGES_CONFIG)
    resolver = DotnetResolver()
    packages = resolver.resolve(str(project))
    assert len(packages) == 3
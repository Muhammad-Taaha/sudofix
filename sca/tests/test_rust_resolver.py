from pathlib import Path
from sca.resolver.plugins.rust import RustResolver

def test_rust_resolver(tmp_path):
    project = tmp_path / "rust_app"
    project.mkdir()
    cargo_lock = """[[package]]
name = "serde"
version = "1.0.152"
[[package]]
name = "tokio"
version = "1.25.0"
"""
    (project / "Cargo.lock").write_text(cargo_lock)
    resolver = RustResolver()
    packages = resolver.resolve(str(project))
    assert len(packages) == 2
    names = {p.name for p in packages}
    assert names == {"serde", "tokio"}
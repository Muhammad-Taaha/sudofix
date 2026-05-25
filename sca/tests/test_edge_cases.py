import pytest
from pathlib import Path
from sca import analyze

def test_scan_empty_directory(tmp_path):
    result = analyze(str(tmp_path))
    assert result["status"] == "ok"
    # Should still succeed (with no findings)
    sub = result["sub_projects"][0]
    assert sub["packages"] == []

def test_scan_broken_manifest(tmp_path):
    (tmp_path / "package.json").write_text("{invalid json")
    result = analyze(str(tmp_path))
    assert result["status"] == "ok"
    # Should not crash
    sub = result["sub_projects"][0]
    # The npm resolver will fail silently, so packages may be empty
    assert isinstance(sub["packages"], list)

def test_scan_with_symlink(tmp_path):
    # Symlinks should be handled gracefully (skip or follow)
    target = tmp_path / "target"
    target.write_text("hello")
    link = tmp_path / "link"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Symlink creation not allowed")
    result = analyze(str(tmp_path))
    assert result["status"] == "ok"
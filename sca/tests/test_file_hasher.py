import os
import time
from pathlib import Path

from sca.file_hasher import discover_files, hash_files


def test_discover_files_basic(fake_project):
    files = discover_files(fake_project)
    # main.py, script.js, readme.txt (node_modules is ignored by default ignore patterns)
    paths = {f.name for f in files}
    assert paths == {"main.py", "script.js", "readme.txt"}


def test_discover_files_respects_gitignore(fake_project):
    # .gitignore contains *.pyc, /dist
    # Add a .pyc file and a dist directory
    pyc = fake_project / "test.pyc"
    pyc.write_text("")
    dist_dir = fake_project / "dist" / "bundle.js"
    dist_dir.parent.mkdir()
    dist_dir.write_text("")
    files = discover_files(fake_project)
    names = {f.name for f in files}
    assert "test.pyc" not in names
    assert "bundle.js" not in names


def test_discover_files_max_size(fake_project):
    # Create a file larger than 1 byte but set max_file_size_mb=0.0 to skip everything
    (fake_project / "big.txt").write_text("a" * 1000)
    files = discover_files(fake_project, max_file_size_mb=0.00001)  # 0.01 KB
    # only the file smaller than ~10 bytes should remain – big.txt should be skipped
    # readme.txt, main.py, script.js are all very small
    assert "big.txt" not in {f.name for f in files}


def test_hash_files_integrity(fake_project):
    paths = discover_files(fake_project)
    results = hash_files(paths)
    assert len(results) == len(paths)
    for p, h, mtime in results:
        assert len(h) == 64
        assert isinstance(mtime, float)
        # file must exist
        assert Path(p).exists()


def test_hash_files_parallel_speed(fake_project, tmp_path):
    # Create 100 dummy files and ensure speedup (rough check)
    for i in range(100):
        (tmp_path / f"dummy_{i}.txt").write_text(f"content {i}")
    paths = list(tmp_path.glob("dummy_*.txt"))
    start = time.time()
    results = hash_files(paths, max_workers=4)
    elapsed = time.time() - start
    assert len(results) == 100
    # Very loose check – it should complete quickly
    assert elapsed < 5

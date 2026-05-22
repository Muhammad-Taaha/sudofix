import subprocess
import pytest
from pathlib import Path
from sca.git_history import GitHistoryScanner

@pytest.fixture
def git_repo(tmp_path):
    """Create a temporary git repo with a few commits."""
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=str(repo), check=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=str(repo), check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=str(repo), check=True)

    # First commit: add a file
    (repo / "old.js").write_text("console.log('old');")
    subprocess.run(["git", "add", "old.js"], cwd=str(repo), check=True)
    subprocess.run(["git", "commit", "-m", "first"], cwd=str(repo), check=True)

    # Second commit: delete that file
    (repo / "old.js").unlink()
    subprocess.run(["git", "add", "-A"], cwd=str(repo), check=True)
    subprocess.run(["git", "commit", "-m", "delete old.js"], cwd=str(repo), check=True)

    return repo

def test_git_history_scanner_finds_deleted_file(git_repo, tmp_path):
    scanner = GitHistoryScanner(str(git_repo), cache_dir=str(tmp_path))
    findings = scanner.scan()
    # Should find the deleted file in the second commit
    assert len(findings) >= 1
    assert findings[0].file_path == "old.js"
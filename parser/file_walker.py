import subprocess
from typing import List, Dict


class RepoWalker:
    def __init__(self, repo_path: str):
        self.repo_path = repo_path

    # -----------------------------
    # Tracked (committed) files
    # -----------------------------
    def get_tracked_files(self) -> List[str]:
        result = subprocess.run(
            ["git", "ls-files"],
            cwd=self.repo_path,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if result.returncode != 0:
            raise RuntimeError(f"Git error: {result.stderr}")

        return result.stdout.strip().splitlines()

    # ----------------------------------
    # Working tree changes (diff)
    # ----------------------------------
    def get_working_tree_changes(self) -> List[Dict]:
        """
        Returns:
        [
          {"status": "M", "file": "parser/repo_parser.py"},
          {"status": "A", "file": "new_file.py"}
        ]
        """
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=self.repo_path,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if result.returncode != 0:
            raise RuntimeError(f"Git error: {result.stderr}")

        changes = []

        for line in result.stdout.splitlines():
            status = line[:2].strip()
            file_path = line[3:].strip()

            changes.append({
                "status": status,
                "file": file_path
            })

        return changes

    def has_uncommitted_changes(self) -> bool:
        return len(self.get_working_tree_changes()) > 0

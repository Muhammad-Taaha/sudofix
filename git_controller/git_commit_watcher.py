import subprocess
from typing import List, Optional, Dict
from datetime import datetime


class GitCommitWatcher:
    """
    Tracks git changes in a repository.
    Monitors commits, branches, and staged changes.
    """
    def __init__(self, repo_path: str):
        self.repo_path = repo_path

    def get_last_commit_hash(self) -> str:
        """Get the latest commit hash (HEAD)"""
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=self.repo_path
        ).decode().strip()

    def get_commit_details(self, commit_hash: str) -> Dict[str, str]:
        """Get detailed information about a commit"""
        output = subprocess.check_output(
            ["git", "show", "--format=%H%n%an%n%ae%n%aI%n%s", "-s", commit_hash],
            cwd=self.repo_path
        ).decode().strip().split('\n')
        
        return {
            "hash": output[0] if len(output) > 0 else None,
            "author": output[1] if len(output) > 1 else None,
            "email": output[2] if len(output) > 2 else None,
            "date": output[3] if len(output) > 3 else None,
            "message": output[4] if len(output) > 4 else None,
        }

    def get_commit_diff(self, commit_hash: str) -> str:
        """Get diff for a specific commit"""
        return subprocess.check_output(
            ["git", "show", commit_hash],
            cwd=self.repo_path
        ).decode()

    def get_staged_diff(self) -> str:
        """Get diff of staged changes"""
        return subprocess.check_output(
            ["git", "diff", "--cached"],
            cwd=self.repo_path
        ).decode()

    def get_unstaged_diff(self) -> str:
        """Get diff of unstaged changes"""
        return subprocess.check_output(
            ["git", "diff"],
            cwd=self.repo_path
        ).decode()

    def get_changed_files_between_commits(self, commit1: str, commit2: str) -> List[str]:
        """Get list of files changed between two commits"""
        return subprocess.check_output(
            ["git", "diff", "--name-only", commit1, commit2],
            cwd=self.repo_path
        ).decode().strip().split('\n')

    def get_changed_files_in_commit(self, commit_hash: str) -> List[str]:
        """Get list of files changed in a specific commit"""
        return subprocess.check_output(
            ["git", "diff-tree", "--no-commit-id", "--name-only", "-r", commit_hash],
            cwd=self.repo_path
        ).decode().strip().split('\n')

    def get_current_branch(self) -> str:
        """Get the current branch name"""
        return subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=self.repo_path
        ).decode().strip()

    def get_branches(self) -> List[str]:
        """Get list of all branches"""
        output = subprocess.check_output(
            ["git", "branch", "-a"],
            cwd=self.repo_path
        ).decode().strip()
        return [b.strip().lstrip('*').strip() for b in output.split('\n') if b.strip()]

    def get_commit_log(self, limit: int = 10) -> List[Dict[str, str]]:
        """Get recent commit history"""
        output = subprocess.check_output(
            ["git", "log", f"--max-count={limit}", "--format=%H|%an|%ae|%aI|%s"],
            cwd=self.repo_path
        ).decode().strip().split('\n')
        
        commits = []
        for line in output:
            parts = line.split('|')
            if len(parts) >= 5:
                commits.append({
                    "hash": parts[0],
                    "author": parts[1],
                    "email": parts[2],
                    "date": parts[3],
                    "message": parts[4],
                })
        return commits

    def has_uncommitted_changes(self) -> bool:
        """Check if there are uncommitted changes"""
        try:
            subprocess.check_output(
                ["git", "diff", "--quiet"],
                cwd=self.repo_path
            )
            return False
        except subprocess.CalledProcessError:
            return True

    def get_status(self) -> str:
        """Get git status output"""
        return subprocess.check_output(
            ["git", "status", "--porcelain"],
            cwd=self.repo_path
        ).decode()

from .git_commit_watcher import GitCommitWatcher
import subprocess


class Checker:
    def __init__(self, command, repo_path=None, repo_scanner=None, db=None):
        self.commad = command
        self.repo_path = repo_path
        self.repo_scanner = repo_scanner
        self.db = db

    def sync_git_changes(self):
        # 1. Get files changed in the last commit
        changed_files = subprocess.check_output(
            ["git", "diff", "HEAD~1", "HEAD", "--name-only"],
            cwd=self.repo_path
        ).decode().splitlines()

        for file_path in changed_files:
            # 2. Trigger your Incremental Scanner
            # This only parses the modified file
            new_chunks = self.repo_scanner.github_webhook_scanner([file_path])

            # 3. Compare Hashes
            for chunk in new_chunks:
                # If hash is different from Postgres, it's a "Dirty Entity"
                # Mark it for re-documentation/review
                self.db.mark_entity_as_dirty(chunk['chunk_hash'])
                self.db.mark_entity_as_dirty(chunk['chunk_hash'])
    

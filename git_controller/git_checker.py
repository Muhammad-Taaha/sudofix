from .git_commit_watcher import GitCommitWatcher
import subprocess
from typing import Optional, List, Dict


class Checker:
    """
    Checks and syncs git changes with the codebase.
    Processes commits and marks entities for re-analysis.
    """
    def __init__(self, command: str, repo_path: Optional[str] = None, repo_scanner=None, db=None):
        self.command = command
        self.repo_path = repo_path
        self.repo_scanner = repo_scanner
        self.db = db
        if repo_path:
            self.git_watcher = GitCommitWatcher(repo_path)
        else:
            self.git_watcher = None

    def sync_git_changes(self) -> Dict[str, int]:
        """
        Sync recent git changes:
        1. Get files changed in last commit
        2. Re-parse changed files
        3. Mark dirty entities for re-analysis
        """
        if not all([self.repo_path, self.repo_scanner, self.db, self.git_watcher]):
            raise ValueError("repo_path, repo_scanner, and db required for sync_git_changes")
        
        stats = {"files_processed": 0, "chunks_updated": 0, "entities_marked_dirty": 0}
        
        try:
            # Get files changed in the last commit
            changed_files = self.git_watcher.get_changed_files_between_commits("HEAD~1", "HEAD")
            
            for file_path in changed_files:
                if not file_path.strip():
                    continue
                    
                stats["files_processed"] += 1
                
                # Trigger incremental scanner for modified file
                new_chunks = self.repo_scanner.github_webhook_scanner([file_path])
                stats["chunks_updated"] += len(new_chunks)
                
                # Mark dirty entities for re-analysis
                for chunk in new_chunks:
                    if 'chunk_hash' in chunk:
                        self.db.mark_entity_as_dirty(chunk['chunk_hash'])
                        stats["entities_marked_dirty"] += 1
        
        except subprocess.CalledProcessError as e:
            print(f"Git sync error: {e}")
        
        return stats

    def get_changed_files_since_last_scan(self) -> List[str]:
        """
        Get files changed since the last database scan
        Useful for incremental updates
        """
        if not self.git_watcher:
            raise ValueError("git_watcher not initialized")
        
        try:
            changed_files = self.git_watcher.get_changed_files_between_commits("HEAD~1", "HEAD")
            return [f for f in changed_files if f.strip()]
        except subprocess.CalledProcessError:
            return []

    def get_commit_history(self, limit: int = 10) -> List[Dict]:
        """Get recent commit history"""
        if not self.git_watcher:
            raise ValueError("git_watcher not initialized")
        return self.git_watcher.get_commit_log(limit)

    def has_pending_changes(self) -> bool:
        """Check if there are uncommitted changes"""
        if not self.git_watcher:
            raise ValueError("git_watcher not initialized")
        return self.git_watcher.has_uncommitted_changes()
    

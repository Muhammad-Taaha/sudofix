from controllers.git_commit_watcher import RepoScanner
from collections import Stack 
import subprocess
'''
    this is basically the file that tracks the git status of all the project 
'''
class GitCommitWatcher:
    def __init__(self,repo_path,repo_scanner):
        self.repo_path = repo_path
        self.repo_scanner = repo_scanner
    def get_last_commit_hash(self):
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"]
        ).decode().strip()
    def get_difference_between_commits(self,commit_hash):
        return subprocess.check_output(
            ["git", "show", commit_hash]
        ).decode()
    def get_staged_diff(self):
        return subprocess.check_output(
            ["git","diff","--cached"]
        ).decode()
    def get_unstagged_diff(self):
        return subprocess.check_output(
            ["git","diff"]
        ).decode()
    
    def get_staged_diff(self,mode="committed"):
        return subprocess.check_output(
            ["git", "diff", "--cached"]
        ).decode()


    

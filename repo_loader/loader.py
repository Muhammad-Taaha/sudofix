'''in this file what we have to do is to load the data from the system
then we have to give a check if the document is created upto this file or not 
then we need to check the database we need to do the caching for the roolbacks and the other stuff 
in case of some hazards we have to do the event driven architectures and we have to make sure that the syatem 
just never breaks so that we can feed the code to the llm in the most effective way 
 
'''

# repo_loader/loader.py
import os
import subprocess
from pathlib import Path
from typing import Optional

class RepoLoader:
    def __init__(
        self,
        repo_url: Optional[str] = None,
        local_path: Optional[str] = None,
        branch: str = "main",
        commit: Optional[str] = None,
        token: Optional[str] = None,
        workspace: str = ".repos"
    ):
        self.repo_url = repo_url
        self.local_path = local_path
        self.branch = branch
        self.commit = commit
        self.token = token
        self.workspace = Path(workspace)

    def load(self) -> str:
        if self.local_path:
            return self._load_local()
        if self.repo_url:
            return self._load_remote()
        raise ValueError("Either repo_url or local_path must be provided")

    def _load_local(self) -> str:
        path = Path(self.local_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Repo path not found: {path}")
        return str(path)

    def _load_remote(self) -> str:
        self.workspace.mkdir(exist_ok=True)
        repo_name = self.repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        repo_dir = self.workspace / repo_name

        if not repo_dir.exists():
            self._clone_repo(repo_dir)

        if self.branch:
            self._checkout(repo_dir, self.branch)

        if self.commit:
            self._checkout(repo_dir, self.commit)

        return str(repo_dir)

    def _clone_repo(self, repo_dir: Path):
        url = self.repo_url
        if self.token:
            url = url.replace("https://", f"https://{self.token}@")

        try:
            subprocess.run(
                ["git", "clone", url, str(repo_dir)],
                check=True,
                capture_output=True,
                text=True
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to clone repository: {e.stderr}")

    def _checkout(self, repo_dir: Path, ref: str):
        try:
            subprocess.run(
                ["git", "checkout", ref],
                cwd=repo_dir,
                check=True,
                capture_output=True,
                text=True
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to checkout {ref}: {e.stderr}")

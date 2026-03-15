from typing import List, Optional
from pathlib import Path
from parser.file_walker import RepoWalker
from parser.detectors import FileDetector
from parser.repo_parser import RepoParser
import os 

class RepoScanner:
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.walker = RepoWalker(self.repo_path)
        self.detector = FileDetector(repo_path)
        self.parser = RepoParser(repo_path)
    # -------------------------
    # 1 Local Scanner
    # -------------------------
    def local_scanner(self):
        files = self.walker.get_tracked_files()
        parsed_chunks = []
        excluded_files = {'.env', 'package-lock.json', 'yarn.lock', '.gitignore'}
        excluded_dirs = {'.git', '__pycache__', 'node_modules', 'venv', '.venv'}
        for file_path in files:
            if not os.path.exists(file_path): # this is for checking if we have changed the file path or not 
                print(f"⚠️ Warning: File not found on disk, skipping: {file_path}")
                continue
            # Convert to absolute path if it isn't already
            if file_path in  excluded_files or any(d in file_path for d in excluded_dirs):
                continue
            full_path = os.path.join(self.repo_path, file_path)

            # --- THE FIX: Skip if it's a directory ---
            if os.path.isdir(full_path):
                continue
            # -----------------------------------------

            detected = self.detector.get_file_metadata(full_path)
            if not detected:
                continue

            detected["file_path"] = full_path
            chunks = self.parser.parse_file(metadata=detected)
            parsed_chunks.extend(chunks)

        return parsed_chunks

    # -------------------------
    # 2️⃣ GITHUB WEBHOOK SCANNER
    # -------------------------

    def github_webhook_scanner(self, changed_files: List[str]):
        """
        Incremental scan (webhook-based)
        """
        parsed_chunks = []

        for relative_path in changed_files:
            file_path = self.repo_path / relative_path

            if not file_path.exists():
                continue

            detected = self.detector.detect(file_path)
            if not detected:
                continue

            chunks = self.parser.parse(
                file_path=file_path,
                file_type = detected.get('file_type'),
                language=detected.language,
                incremental=True
            )

            parsed_chunks.extend(chunks)

        return parsed_chunks
    
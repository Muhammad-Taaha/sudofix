from typing import List, Optional
from pathlib import Path

from parser.file_walker import RepoWalker
from parser.detectors import FileDetector
from parser.repo_parser import RepoParser

class RepoScanner:
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)

        self.walker = RepoWalker(self.repo_path)
        self.detector = FileDetector()
        self.parser = RepoParser()

    # -------------------------
    # 1️⃣ LOCAL SCANNER
    # -------------------------
    def local_scanner(self):
        """
        Full repo scan (initial indexing)
        """
        files = self.walker.get_tracked_files()

        parsed_chunks = []

        for file_path in files:
            detected = self.detector.detect(file_path)

            if not detected:
                continue

            chunks = self.parser.parse(
                file_path=file_path,
                file_type=detected.file_type,
                language=detected.language
            )

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
                file_type=detected.file_type,
                language=detected.language,
                incremental=True
            )

            parsed_chunks.extend(chunks)

        return parsed_chunks

from controllers.repo_scanner import RepoScanner
from vector_store.store import VectorStore
from llm.ollama_client import OllamaClient
# main function


class RepoPipeline:
    def __init__(self, repo_path: str):
        self.scanner = RepoScanner(repo_path)
        self.vector_store = VectorStore()
        self.llm = OllamaClient()

    def full_index(self):
        chunks = self.scanner.local_scanner()

        for chunk in chunks:
            embedding = self.llm.embed(chunk.content)
            self.vector_store.store(chunk, embedding)

    def incremental_update(self, changed_files):
        chunks = self.scanner.github_webhook_scanner(changed_files)

        for chunk in chunks:
            embedding = self.llm.embed(chunk.content)
            self.vector_store.upsert(chunk, embedding)

from controllers.reddis_controller import RedisManager
from controllers.data_base_controller import Postgres
from controllers.repo_scanner import RepoScanner, RepoWalker, RepoParser
from vector_store.store import VectorStore
from llm.ollama_client import ollama_client
from git_controller.git_checker import Checker
from controllers.reddis_controller import RedisManager
# in this part i will deal with the orchasteration of the code with the llms so that the highest quality of the code is avaiable to me


class CliAgent:
    def __init__(self, repo_path: str, ):
        # Ensure these are initialized correctly
        self.parser = RepoParser(repo_path)
        self.walker = RepoWalker(repo_path)
        self.scanner = RepoScanner(repo_path)
        self.vector_store = VectorStore()  # Ensure this auto-dims as discussed
        self.llm = ollama_client()
        self.reddis_manager = RedisManager()
        self.git_controller = Checker()

    def _process_logic(self, chunk, task_prompt):
        """Helper to handle the repetitive logic of checking, parsing, and LLM calls."""
        # 1. Check Metadata
        meta = self.parser._build_chunk().get("metadata", {})
        if meta.get("language") != "Python":
            return None

        # 2. Check Git Changes (Optimization)
        if not self.git_controller.sync_git_changes(chunk):
            print("No changes detected. Skipping...")
            return None

        # 3. LLM Interaction
        # Note: chunk should be a list of strings (functions/classes)
        # If it's one big string, wrap it in a list: [chunk]
        contents = chunk if isinstance(chunk, list) else [chunk]

        for content in contents:
            prompt = f"{task_prompt}\n\nCode:\n{content}"
            response = self.llm.generate(prompt)

            if not response:
                raise RuntimeError("LLM failed to generate a response.")

            print(f"\n🧠 LLM OUTPUT:\n{response}")

            # 4. Cache and Vectorize
            self.caching_the_respone(content, response)
            # Store the insight for future RAG
            self.make_vector(content, response)

        return True

    def review_code(self, chunk):
        prompt = "You are a senior engineer. Review this code for edge cases and architecture."
        return self._process_logic(chunk, prompt)

    def generate_test(self, chunk):
        prompt = "You are a senior engineer. Generate high-quality unit tests for this code."
        return self._process_logic(chunk, prompt)

    def generate_documentation(self, chunk):
        prompt = "You are a senior engineer. Write professional technical documentation."
        return self._process_logic(chunk, prompt)

    def caching_the_respone(self, chunk, response):
        # We use a hash of the chunk as the key to avoid Redis collisions
        import hashlib
        key = hashlib.sha256(chunk.encode()).hexdigest()
        self.reddis_manager.save_to_reddis(key, response.strip())

    def make_vector(self, chunk, response):
        meta_data = self.parser._build_chunk()  # Ensure this returns a dict
        # We store the response (the insight) associated with the code
        self.vector_store.add([chunk], [{"response": response, **meta_data}])

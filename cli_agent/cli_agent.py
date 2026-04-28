import hashlib  # this is for the forming of the hash functions
from controllers.reddis_controller import RedisManager
from controllers.repo_scanner import RepoScanner, RepoWalker, RepoParser
from vector_store.store import VectorStore
from llm.ollama_client import OllamaClient
from git_controller.git_checker import Checker
import traceback
from controllers.data_base_controller import Postgres

class CliAgent:
    def __init__(self, repo_path, command):
        # We initialize these to use their internal logic
        # Note: We don't need self.parser for building chunks anymore
        self.repo_path = repo_path
        self.vector_store = VectorStore()  # Ensure your Store class auto-dims
        self.llm = OllamaClient()
        self.reddis_manager = RedisManager()
        self.redis_client = self.reddis_manager.connect()
        self.git_controller = Checker(command)
        self.data_base = Postgres()

    def _process_logic(self, chunk_dict, task_prompt):
        content = chunk_dict.get("content", "")
        metadata = chunk_dict.get("metadata", {})
        file_name = chunk_dict.get("file_name", "Unknown File")

        # 🔍 DEBUG: See what the parser actually found
        detected_lang = metadata.get("language", "EMPTY")
        print(f"🔎 Checking {file_name} | Language: {detected_lang}")

        # 2. Language Filter - Let's make it more flexible
        if detected_lang.lower() not in ["python", "py"]:
            print(f"❌ Skipping {file_name}: Not a Python file.")
            return None

        # 4. LLM Interaction
        print(f"📡 SENDING TO OLLAMA: {file_name} (This should take time...)")
        prompt = f"{task_prompt}\n\nCode Content:\n{content}"

        try:
            # If Ollama is working, it WILL be slow here
            response = self.llm.generate(prompt)

            if not response:
                print(f"⚠️ LLM returned empty for {file_name}")
                return None

            print(f"✅ LLM SUCCESS: Generated response for {file_name}")

            # 5. Persistence
            self.caching_the_response(content, response)
            print("Saved to the reddis")
            self.make_vector(chunk_dict, response)
            print("Made the vector embedding")
            return response
        except Exception as e:
            traceback.print_exc()
            return None

    def review_code(self, chunk_dict):
        prompt = "You are a senior engineer. Review this code for edge cases, security, and architecture."
        return self._process_logic(chunk_dict, prompt)

    def generate_test(self, chunk_dict):
        prompt = "You are a senior engineer. Generate high-quality unit tests using pytest for this code."
        return self._process_logic(chunk_dict, prompt)

    def generate_documentation(self, chunk_dict):
        prompt = "You are a senior engineer. Write professional technical documentation (docstrings and logic explanation)."
        return self._process_logic(chunk_dict, prompt)

    def caching_the_response(self, content, response):
        """Saves LLM output to Redis using a hash of the code as the key."""
        key = hashlib.sha256(content.encode()).hexdigest()
        self.reddis_manager.save_to_reddis(key, response.strip())

    def make_vector(self, chunk_dict, response):
        """Stores the code and the AI insight in FAISS."""
        try:
            # Enrich the existing dictionary with the AI's response
            enriched_metadata = {
                **chunk_dict,  # this is the code wich tells the chunk which is provided to the llm for the inference
                "llm_insight": response
            }

            print(f"the vector of the file is {chunk_dict.get('file_name')} ")

            # We embed the original code, but store the AI insight alongside it
            self.vector_store.add([chunk_dict["content"]], [enriched_metadata])
            save_dir = "vector_store"
            self.vector_store.save(save_dir)
                        
            print(f"✅ Vector Store updated and saved to {save_dir}/")
        except Exception as e:
            print(f"❌ Error updating vector store: {e}")
            traceback.print_exc()
            return None

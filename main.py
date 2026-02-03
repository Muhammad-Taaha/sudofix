# main.py

from controllers.data_base_controller import Postgres
from controllers.reddis_controller import RedisManager
from controllers.repo_scanner import RepoScanner
from parser.repo_parser import RepoParser
from parser.chuncker.python_chuncker import PythonChunker
from llm.ollama_client import OllamaClient
import os

def run_llm(repo_path: str):
    print("🚀 Starting Repo-LLM pipeline")

    # --------------------------
    # 1. Database connection
    # --------------------------
    db = Postgres()
    connection = db.connect()
    if not connection:
        raise RuntimeError("❌ Database connection failed")
    print("✅ Database connected")

    # --------------------------
    # 2. Redis connection
    # --------------------------
    cache = RedisManager()
    redis_client = cache.connect()
    if not redis_client:
        raise RuntimeError("❌ Redis connection failed")
    print("✅ Redis connected")

    # --------------------------
    # 3. Scan repo
    # --------------------------
    scanner = RepoScanner()
    files = scanner.local_scanner(repo_path)
    print(f"📂 Found {len(files)} files")
    if len(files) == 0:
        print("⚠ No files found. Exiting...")
        return

    # --------------------------
    # 4. Parse first file
    # --------------------------
    parser = RepoParser()
    parsed_file = parser.parse_file(files[0])
    print(f"🧩 Parsed file: {parsed_file['path']}")

    # --------------------------
    # 5. Chunk the file
    # --------------------------
    chunker = PythonChunker()
    chunks = chunker.chunk(parsed_file)
    print(f"🔹 Created {len(chunks)} chunks")

    # --------------------------
    # 6. Call LLM for each chunk (demo)
    # --------------------------
    llm = OllamaClient()
    for i, chunk in enumerate(chunks):
        prompt = f"""
You are a senior software engineer.
Explain what this code does in detail:

{chunk['content']}
"""
        response = llm.generate(prompt)
        print(f"\n🧠 LLM OUTPUT FOR CHUNK {i+1}:\n")
        print(response)
        # Only demo one chunk for brevity
        if i == 0:
            break


if __name__ == "__main__":
    # Change this path to the repo you want to scan
    repo_path = os.path.abspath(".")
    run_llm(repo_path)

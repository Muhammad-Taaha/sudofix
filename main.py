# main.py

from controllers.data_base_controller import Postgres
from controllers.reddis_controller import RedisManager
from controllers.repo_scanner import RepoScanner
from parser.repo_parser import RepoParser
from llm.ollama_client import OllamaClient
import os
import argparse


def run_llm(repo_path: str):
    print("\n🚀 Starting Repo-LLM pipeline")

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
    # 3. Scan & Parse Repo
    # --------------------------
    print(f"🔍 Scanning directory: {repo_path}")
    scanner = RepoScanner(repo_path)

    # This method already calls RepoParser internally for every file
    all_chunks = scanner.local_scanner()

    if not all_chunks:
        print("❌ No chunks were generated. Check if the directory contains supported files (Py, Rust, C++).")
        return

    print(f"📂 Total chunks found across all files: {len(all_chunks)}")

    # --------------------------
    # 4. Process Chunks with LLM
    # --------------------------
    llm = OllamaClient()

    # We will demonstrate with the first few chunks
    for i, chunk in enumerate(all_chunks):
        # The key is 'file_path' (from your RepoParser._build_chunk)
        file_name = chunk.get('file_name', 'Unknown File')
        content = chunk.get('content', '')

        print(f"\n--- Processing Chunk {i+1} from {file_name} ---")

        if not content.strip():
            print("⚠ Chunk has no content, skipping...")
            continue

        prompt = f"""
        You are a senior software engineer.
        Explain what this code does in detail:
        {content}
        """

        print(f"📡 Sending to Ollama (this may take a moment)...")
        try:
            response = llm.generate(prompt)
            print(f"\n🧠 LLM OUTPUT:\n")
            print(response)
        except Exception as e:
            print(f"❌ Error calling Ollama: {e}")

        # BREAK after the first chunk for the demo.
        # Remove these lines to process the WHOLE repo.
        if i == 0:
            print("\n⏹ Demo mode: Stopping after the first chunk.")
            break


if __name__ == "__main__":
    # Ensure we use an absolute path
    parser = argparse.ArgumentParser(
        description="AI-Powered Repository Code Review Tool")

    # Add Positional Argument: The path to the repo
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to the target repository (default: current directory)"
    )

    # Add Optional Flag: Demo mode
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run in demo mode (process only the first chunk)"
    )

    args = parser.parse_args()

    # Convert path to absolute to avoid issues with relative directories
    abs_path = os.path.abspath(args.path)

    # Validate if path exists
    if not os.path.exists(abs_path):
        print(f"❌ Error: The path '{abs_path}' does not exist.")
    else:
        run_llm(abs_path, args.demo)

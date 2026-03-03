import os
import argparse
from cli_agent.cli_agent import CliAgent
from controllers.data_base_controller import Postgres
from controllers.reddis_controller import RedisManager
from controllers.repo_scanner import RepoScanner

def run_llm(repo_path: str, command: str):
    print("\n🚀 Starting Repo-LLM pipeline")

    # 1. Database connection
    db = Postgres()
    if not db.connect():
        raise RuntimeError("❌ Database connection failed")
    print("✅ Database connected")

    # 2. Redis connection
    cache = RedisManager()
    if not cache.connect():
        raise RuntimeError("❌ Redis connection failed")
    print("✅ Redis connected")

    # 3. Scan & Parse Repo
    print(f"🔍 Scanning directory: {repo_path}")
    scanner = RepoScanner(repo_path)
    all_chunks = scanner.local_scanner()

    if not all_chunks:
        print("❌ No chunks were generated. Check for supported files (.py, .rs, .cpp).")
        return

    print(f"📂 Total chunks found across all files: {len(all_chunks)}")

    # 4. Agent Orchestration
    try:
        agent = CliAgent(repo_path, command)
        
        for i, chunk in enumerate(all_chunks):
            file_name = chunk.get('file_name', 'Unknown File')
            print(f"\n🔄 [{i+1}/{len(all_chunks)}] Processing: {file_name}")

            # Trigger the agent based on the command
            if command == "review":
                agent.review_code(chunk)
            elif command == "test":
                agent.generate_test(chunk)
            elif command == "doc":
                agent.generate_documentation(chunk)
                
    except Exception as e:
        print(f"❌ Error during agent execution: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI Senior Engineer Agent")
    parser.add_argument("path", nargs="?", default=".", help="Repo path")
    
    subparsers = parser.add_subparsers(dest="command", required=True, help="Modes")
    subparsers.add_parser("review", help="Review code architecture")
    subparsers.add_parser("test", help="Generate unit tests")
    subparsers.add_parser("doc", help="Generate documentation")

    args = parser.parse_args()
    abs_path = os.path.abspath(args.path)

    if not os.path.exists(abs_path):
        print(f"❌ Error: {abs_path} not found.")
    else:
        run_llm(abs_path, args.command)

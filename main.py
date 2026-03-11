# main.py
from cli_agent.cli_agent import CliAgent
from controllers.data_base_controller import Postgres
from controllers.reddis_controller import RedisManager
from controllers.repo_scanner import RepoScanner
from parser.repo_parser import RepoParser
from llm.ollama_client import OllamaClient
import os
import argparse
import sys #this is for the grace-ful shut down 
import hashlib

def run_llm(repo_path: str, command):
    print("\n🚀 Starting Repo-LLM pipeline")

    db = None
    cache = None
    connection = None
    redis_client = None

    try:
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

        all_chunks = scanner.local_scanner()

        if not all_chunks:
            print("❌ No chunks found.")
            return

        print(f"📂 Total chunks: {len(all_chunks)}")

        agent = CliAgent(repo_path, command)

        for chunk in all_chunks:
            
            content_hash = hashlib.sha256(chunk['content'].encode()).hexdigest()
            if redis_client.get(content_hash):
                            print(f"⏩ Skipping {chunk['file_name']}: Already in Cache")
                            continue
            # graceful stop check
            user_input = input("Press Enter to continue or q to quit: ")

            if user_input.lower() == "q":
                print("🛑 Shutdown requested by user")
                break

            if command == "review":
                agent.review_code(chunk)
                
            elif command == "test":
                agent.generate_test(chunk)
                
            elif command == "doc":
                agent.generate_documentation(chunk)
                        
    except KeyboardInterrupt:
        print("\n⚠️ Interrupt received. Shutting down safely...")

    except Exception as e:
        print("❌ Error:", e)

    finally:
        print("🔻 Cleaning resources...")

        if connection:
            connection.close()
            print("✅ Database connection closed")

        if redis_client:
            redis_client.close()
            print("✅ Redis connection closed")

        print("👋 Program exited safely")
        sys.exit(0)
        
            
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI Senior Engineer Agent")
    
    # Global Path Argument
    parser.add_argument("path", nargs="?", default=".", help="Repo path")

    # Create Subcommands
    subparsers = parser.add_subparsers(dest="command", required=True, help="Modes")
    
    subparsers.add_parser("review", help="Review code architecture")
    subparsers.add_parser("test", help="Generate unit tests")
    subparsers.add_parser("doc", help="Generate documentation")

    args = parser.parse_args()
    abs_path = os.path.abspath(args.path)

    if not os.path.exists(abs_path):
        print(f"❌ Error: {abs_path} not found.")
    else:
        # Pass both the path and the command (review/test/doc)
        run_llm(abs_path, args.command)


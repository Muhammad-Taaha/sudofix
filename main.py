import os
import argparse
import sys
import hashlib
from cli_agent.cli_agent import CliAgent
from controllers.data_base_controller import Postgres
from controllers.reddis_controller import RedisManager
from controllers.repo_scanner import RepoScanner

def run_llm(repo_path: str, command: str):
    print(f"\n🚀 Starting Repo-LLM pipeline | Mode: {command}")

    # Initialize Controllers
    db = Postgres()
    cache = RedisManager()
    
    # Established connections
    db_conn = db.connect() # Required to check if DB is alive
    redis_client = cache.connect()

    if not db_conn or not redis_client:
        print("❌ Critical Failure: Could not connect to services.")
        return

    try:
        # 1. Sync the repository structure to Postgres
        # This ensures files and code_entities exist before we try to link insights
        print("🔄 Syncing repository structure to Database...")
        db.sync_repo_to_db(repo_path)

        # 2. Get the local chunks from scanner
        scanner = RepoScanner(repo_path)
        all_chunks = scanner.local_scanner()

        if not all_chunks:
            print("❌ No chunks found or all files excluded.")
            return

        print(f"📂 Total chunks to evaluate: {len(all_chunks)}")
        agent = CliAgent(repo_path, command)

        for chunk in all_chunks:
            content = chunk.get('content', '')
            file_name = os.path.basename(chunk.get('file_path', 'unknown'))
            
            # Generate unique hash for the Specific Content + Specific Task
            content_hash = hashlib.sha256(f"{command}:{content}".encode()).hexdigest()

            # CHECK REDIS CACHE (Fast skip)
            if redis_client.get(content_hash):
                print(f"⏩ Skipping {file_name}: Already processed for {command}")
                continue

            # USER INTERRUPT CHECK
            print(f"\n--- Target: {file_name} ---")
            user_input = input(f"Ready to {command}? [Enter to continue / 'q' to quit]: ")
            if user_input.lower() == "q":
                print("🛑 Shutdown requested by user.")
                break

            # 3. EXECUTE COMMAND
            result = ""
            try:
                # FIXED
                if command == "review":
                    result = agent.review_code(chunk) # Pass the whole chunk dict
                elif command == "test":
                    result = agent.generate_test(chunk)
                elif command == "doc":
                    result = agent.generate_documentation(chunk)            
            except Exception as e:
                print(f"❌ LLM Error: {e}")
                continue

            # 4. SAVE TO POSTGRES
            # We must find the ID assigned by Postgres during the sync step
            # Assuming your scanner/parser provides the entity name or specific hash
            entity_name = chunk['metadata'].get('name', 'anonymous_block')
            entity_hash = chunk['metadata'].get('hash')
            
            # Helper to find the database ID for the code we just processed
            entity_id = db.get_entity_id_by_hash(entity_hash) 
            
            if entity_id:
                db.save_ai_insight(
                    entity_id=entity_id,
                    insight_text=result,
                    task_type=command,
                    model="qwen-7b"
                )
                print(f"💾 Insight saved to Postgres (ID: {entity_id})")

            # 5. UPDATE REDIS CACHE
            redis_client.set(content_hash, "completed", ex=86400) # 24h expiry
            print(f"✅ Cache updated for {file_name}")

    except KeyboardInterrupt:
        print("\n⚠️ Operation cancelled by user.")
    except Exception as e:
        print(f"❌ Unexpected Error: {e}")
    finally:
        print("\n🔻 Cleaning resources...")
        if db_conn:
            db_conn.close()
            print("✅ Database connection closed")
        if redis_client:
            redis_client.close()
            print("✅ Redis connection closed")
        print("👋 Program exited safely")

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
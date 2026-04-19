import os
import argparse
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
    db_conn = db.connect()  
    redis_client = cache.connect()

    if not db_conn or not redis_client:
        print("❌ Critical Failure: Could not connect to services.")
        return

    try:
        # 1. Sync the repository structure to Postgres
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

        # We need the repo_id for lookups
        repo_name = os.path.basename(repo_path)
        repo_data = db.save_repository(repo_name, repo_path)
        repo_id = repo_data[0]['id']

        for chunk in all_chunks:
            content = chunk.get('content', '')
            file_path = chunk.get('file_path')
            file_name = os.path.basename(file_path if file_path else 'unknown')

            # Generate unique hash for the Specific Content + Specific Task
            content_hash = hashlib.sha256(
                f"{command}:{content}".encode()).hexdigest()

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

            # 3. EXECUTE LLM COMMAND
            result = ""
            try:
                if command == "review":
                    result = agent.review_code(chunk)
                elif command == "test":
                    result = agent.generate_test(chunk)
                elif command == "doc":
                    result = agent.generate_documentation(chunk)
                
                if not result:
                    print(f"⚠️ Warning: LLM returned empty result for {file_name}")
                    continue
                    
            except Exception as e:
                print(f"❌ LLM Error: {e}")
                continue

            # 4. SAVE TO POSTGRES
            # Look up the ID based on the file path to find the 'file_root' entity
           # 4. SAVE TO POSTGRES
            # Use the absolute path if that's what's in the DB, or normalize it
            normalized_path = str(file_path) 
            file_record = db._get_file_by_path(repo_id, normalized_path)
            
            entity_id = None
            if file_record:
                # 🔍 DEBUG: print(f"Found file_id: {file_record['id']} for {file_name}")
                sql = "SELECT id FROM code_entities WHERE file_id = %s AND type = 'file_root' LIMIT 1;"
                ent_res = db._execute_query(sql, (file_record['id'],), fetch=True)
                if ent_res:
                    entity_id = ent_res[0]['id']

            if entity_id:
                db.save_ai_insight(
                    entity_id=entity_id,
                    insight_text=result,
                    task_type=command,
                    model="qwen-7b"
                )
                print(f"✅ Saved to Postgres for entity {entity_id}")
                
                # 5. UPDATE REDIS CACHE (Only if DB save succeeded)
                redis_client.set(content_hash, "completed", ex=86400)
                print(f"✅ Cache updated for {file_name}")
            else:
                # 🛠️ HELPER: If entity is missing, it's likely a sync issue
                print(f"❌ Database Error: Could not find entity ID for {file_name}.")
                print(f"   (Hint: Ensure 'code_entities' has a row for file_id {file_record['id'] if file_record else 'NOT FOUND'})")
    except KeyboardInterrupt:
        print("\n⚠️ Operation cancelled by user.")
    except Exception as e:
        print(f"❌ Unexpected Error: {e}")
    finally:
        print("\n🔻 Cleaning resources...")
        # Note: Connections are managed inside controller methods, 
        # but we close the initial check connections here.
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

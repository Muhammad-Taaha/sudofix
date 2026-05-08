import os
import argparse
import hashlib

from cli_agent.cli_agent import CliAgent
from controllers.data_base_controller import Postgres
from controllers.reddis_controller import RedisManager
from controllers.repo_scanner import RepoScanner

from sastscanner.taint.taint_engine import TaintEngine
from sastscanner.core.rule_engine import RuleEngine


# =========================================================
# 🔥 DEBUG UTIL
# =========================================================
def debug(title, data=None):
    print(f"\n🧪 [{title}]")
    if data is not None:
        print(data)


def inspect_nodes(nodes):
    if not isinstance(nodes, list):
        print("⚠️ Nodes not list:", type(nodes))
        return False

    if len(nodes) == 0:
        print("📄 EMPTY AST")
        return False

    print("📄 AST OK | nodes =", len(nodes))

    from collections import Counter
    print("🧪 Sample distribution:")
    print(Counter(getattr(n, "node_type", "unknown") for n in nodes[:50]))

    return True


# =========================================================
# 🚀 PIPELINE
# =========================================================
def run_llm(repo_path: str, command: str):

    print("\n🚀 Starting Repo-LLM pipeline | Mode:", command)

    db = Postgres()
    cache = RedisManager()

    db_conn = db.connect()
    redis_client = cache.connect()

    if not db_conn or not redis_client:
        print("❌ DB/Redis connection failed")
        return

    try:
        print("\n🔄 Syncing repo...")
        db.sync_repo_to_db(repo_path)

        scanner = RepoScanner(repo_path)
        all_chunks = scanner.local_scanner()

        debug("PIPELINE", f"Total chunks = {len(all_chunks)}")

        taint_engine = TaintEngine()
        rule_engine = RuleEngine("sastscanner.rules")

        agent = CliAgent(repo_path, command)

        repo_name = os.path.basename(repo_path)
        repo_data = db.save_repository(repo_name, repo_path)
        repo_id = repo_data[0]["id"]

        # =========================================================
        # MAIN LOOP
        # =========================================================
        for chunk in all_chunks:

            file_path = chunk.get("file_path", "unknown")
            file_name = os.path.basename(file_path)

            language = chunk.get("metadata", {}).get("language", "unknown")
            nodes = chunk.get("nodes") or []

            print("\n" + "=" * 70)

            debug("CHUNK", {
                "file": file_name,
                "language": language,
                "content_len": len(chunk.get("content", "")),
                "nodes": len(nodes)
            })

            print("🔥 CHUNK DEBUG:", len(nodes))
            print(f"\n--- Processing {file_name} ---")

            # =========================================================
            # SKIP INVALID / EMPTY AST EARLY
            # =========================================================
            if not inspect_nodes(nodes):
                print("⏭️ Skipping empty/invalid AST")
                continue

            # =========================================================
            # TAINT ANALYSIS
            # =========================================================
            print("\n🧠 [TAINT DEBUG]")
            try:
                taint_findings = taint_engine.analyze(nodes, language=language)
                taint_findings = taint_findings or []
            except Exception as e:
                print("❌ Taint error:", e)
                taint_findings = []

            print("Taint findings:", len(taint_findings))

            # =========================================================
            # RULE ENGINE
            # =========================================================
            print("\n🛡️ [RULE DEBUG]")
            try:
                rule_findings = rule_engine.scan(
                    chunk,
                    context={
                        "language": language,
                        "taint_findings": taint_findings,
                        "taint_vars": getattr(taint_engine, "state", None),
                    }
                ) or []
            except Exception as e:
                print("❌ Rule engine error:", e)
                rule_findings = []

            print("Rule findings:", len(rule_findings))

            # =========================================================
            # SECURITY SUMMARY
            # =========================================================
            security_findings = (taint_findings or []) + (rule_findings or [])
            print("\n🧪 SECURITY SUMMARY:", len(security_findings))

            # =========================================================
            # LLM STEP (ONLY IF MEANINGFUL DATA EXISTS)
            # =========================================================
            result = None

            try:
                if security_findings or len(nodes) > 5:
                    if command == "review":
                        result = agent.review_code(chunk)
                    elif command == "test":
                        result = agent.generate_test(chunk)
                    elif command == "doc":
                        result = agent.generate_documentation(chunk)
            except Exception as e:
                print("❌ LLM error:", e)

            print("\n🤖 [LLM RESULT]")
            print(bool(result))

            if not result:
                print("⚠️ Empty LLM output (skipped or no issues)")

            # =========================================================
            # CACHE ONLY VALID CHUNKS
            # =========================================================
            content = chunk.get("content", "")
            if content:
                content_hash = hashlib.sha256(
                    f"{command}:{content}".encode()
                ).hexdigest()

                redis_client.set(content_hash, "done", ex=86400)

    except Exception as e:
        print("❌ Pipeline crash:", e)

    finally:
        print("\n🔻 Cleaning up...")
        db_conn.close()
        redis_client.close()
        print("👋 Done")


# =========================================================
# CLI
# =========================================================
if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("path", nargs="?", default=".")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("review")
    sub.add_parser("test")
    sub.add_parser("doc")

    args = parser.parse_args()

    path = os.path.abspath(args.path)

    if not os.path.exists(path):
        print("❌ Path not found:", path)
    else:
        run_llm(path, args.command)
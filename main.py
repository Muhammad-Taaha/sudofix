import os
import argparse
import hashlib
import sys

from cli_agent.cli_agent import CliAgent
from controllers.data_base_controller import Postgres
from controllers.reddis_controller import RedisManager
from controllers.repo_scanner import RepoScanner

from sastscanner.taint.taint_engine import TaintEngine
from sastscanner.core.rule_engine import RuleEngine

# ========== SCA Integration (pure Python wrapper) ==========
# ========== SCA Integration (pure Python wrapper) ==========
SCA_AVAILABLE = False
try:
    import sys
    # Add the top‑level sca/ directory (where sca_simple.py lives)
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'sca'))
    from sca_simple import scan_dependencies
    SCA_AVAILABLE = True
    print("✅ SCA simple scanner loaded")
except ImportError as e:
    print(f"⚠️ SCA simple scanner not found – SCA disabled (error: {e})")
# ============================================================
# ============================================================

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

def run_sca_only(repo_path, command, db, redis_client):
    """Run only SCA analysis using the simple scanner and produce report."""
    print("\n📦 Running SCA only (using simple scanner)...")
    sca_vulns = []
    try:
        # scan_dependencies returns a list of dicts directly
        sca_vulns = scan_dependencies(repo_path)
        print(f"✅ SCA found {len(sca_vulns)} vulnerable dependencies")
        if sca_vulns:
            # Generate report
            report_lines = ["# SCA Vulnerability Report\n"]
            for v in sca_vulns:
                report_lines.append(
                    f"- **{v['package']}** {v['version']} : {v['cve']} "
                    f"(severity: {v['severity']})"
                )
            sca_text = "\n".join(report_lines)
            print("\n" + sca_text)
            # Save to file
            with open("sca_report.md", "w") as f:
                f.write(sca_text)
        else:
            print("No vulnerable dependencies found.")
    except Exception as e:
        print(f"❌ SCA error: {e}")

def run_sast_pipeline(repo_path, command, db, redis_client, sca_vulns=None):
    """Run the full SAST pipeline (taint + rules + LLM) on code chunks."""
    print("\n🔄 Syncing repo for SAST...")
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

    for chunk in all_chunks:
        if "nodes" not in chunk:
            from parser.ast_nodes import UnifiedNode
            chunk["nodes"] = [
                UnifiedNode(
                    node_type="unknown",
                    name=None,
                    code=chunk.get("content", ""),
                    file_path=chunk.get("file_path", "unknown"),
                    start_line=chunk.get("start_line", 0),
                    end_line=chunk.get("end_line", 0),
                    language=chunk.get("metadata", {}).get("language", "unknown"),
                )
            ]

        nodes = chunk.get("nodes", [])
        if not nodes:
            continue

        file_path = chunk.get("file_path", "unknown")
        file_name = os.path.basename(file_path)
        language = chunk.get("metadata", {}).get("language", "unknown")

        print("\n" + "=" * 70)
        debug("CHUNK", {"file": file_name, "language": language, "nodes": len(nodes)})

        if not inspect_nodes(nodes):
            continue

        # Taint analysis
        try:
            taint_findings = taint_engine.analyze(nodes, language=language) or []
        except Exception as e:
            print("❌ Taint error:", e)
            taint_findings = []

        # Rule engine
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

        security_findings = taint_findings + rule_findings

        # SCA context for this chunk (if available)
        chunk_sca = None
        if sca_vulns:
            manifest_names = {"package.json", "Cargo.toml", "requirements.txt",
                              "go.mod", "pom.xml", "build.gradle"}
            if file_name in manifest_names:
                chunk_sca = [v for v in sca_vulns if v.get("file_path") == file_path]
                if not chunk_sca:
                    chunk_sca = {"summary": f"SCA found {len(sca_vulns)} vulnerable dependencies"}
            else:
                chunk_sca = {"summary": f"SCA found {len(sca_vulns)} vulnerable dependencies"}
        chunk['sca_context'] = chunk_sca

        # LLM step
        result = None
        try:
            if security_findings or len(nodes) > 5 or chunk_sca:
                if command == "review":
                    result = agent.review_code(chunk)
                elif command == "test":
                    result = agent.generate_test(chunk)
                elif command == "doc":
                    result = agent.generate_documentation(chunk)
        except Exception as e:
            print("❌ LLM error:", e)

        print("\n🤖 [LLM RESULT]", bool(result))

        # Cache chunk
        content = chunk.get("content", "")
        if content:
            content_hash = hashlib.sha256(f"{command}:{content}".encode()).hexdigest()
            redis_client.set(content_hash, "done", ex=86400)

    # Final SCA summary if both SAST and SCA were run
    if sca_vulns and command == "review":
        print("\n📦 SCA Findings Summary (from earlier):")
        for v in sca_vulns[:5]:
            print(f"  - {v['package']} {v['version']} : {v['cve']}")

def run_llm(repo_path: str, command: str, mode: str):
    """
    mode: 'sast', 'sca', or 'full'
    """
    print(f"\n🚀 Starting pipeline | Mode: {mode.upper()} | Command: {command}")

    db = Postgres()
    cache = RedisManager()
    db_conn = db.connect()
    redis_client = cache.connect()
    if not db_conn or not redis_client:
        print("❌ DB/Redis connection failed")
        return

    try:
        # SCA‑only mode
        if mode == 'sca':
            if not SCA_AVAILABLE:
                print("❌ SCA not available. Install sca_simple.py and required tools.")
                return
            run_sca_only(repo_path, command, db, redis_client)
            return

        # For SAST or full, we may need SCA results
        sca_vulns = None
        if mode == 'full' and SCA_AVAILABLE:
            print("\n📦 Running SCA before SAST (simple scanner)...")
            try:
                sca_vulns = scan_dependencies(repo_path)
                print(f"✅ SCA found {len(sca_vulns)} vulnerable dependencies")
            except Exception as e:
                print(f"❌ SCA error (continuing without SCA): {e}")

        # Run SAST pipeline (with optional SCA context)
        run_sast_pipeline(repo_path, command, db, redis_client, sca_vulns)

    except Exception as e:
        print("❌ Pipeline crash:", e)
    finally:
        print("\n🔻 Cleaning up...")
        db_conn.close()
        redis_client.close()
        print("👋 Done")

# =========================================================
# CLI + Interactive prompt
# =========================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("path", nargs="?", default=".")
    parser.add_argument("--mode", choices=["sast", "sca", "full"],
                        help="Run only SAST, only SCA, or full pipeline")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("review")
    sub.add_parser("test")
    sub.add_parser("doc")

    args = parser.parse_args()

    path = os.path.abspath(args.path)
    if not os.path.exists(path):
        print("❌ Path not found:", path)
        sys.exit(1)

    # Determine mode
    mode = args.mode
    if mode is None:
        print("\n🔍 What would you like to run?")
        print("  1) SAST only (code analysis + LLM)")
        print("  2) SCA only (dependency scanning)")
        print("  3) Full pipeline (both)")
        choice = input("Enter 1, 2, or 3: ").strip()
        if choice == "1":
            mode = "sast"
        elif choice == "2":
            mode = "sca"
        elif choice == "3":
            mode = "full"
        else:
            print("Invalid choice, defaulting to SAST only.")
            mode = "sast"

    run_llm(path, args.command, mode)
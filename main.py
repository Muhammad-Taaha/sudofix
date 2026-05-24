import os
import argparse
import hashlib
import sys
import json

from cli_agent.cli_agent import CliAgent
from controllers.data_base_controller import Postgres
from controllers.reddis_controller import RedisManager
from controllers.repo_scanner import RepoScanner

from sastscanner.taint.taint_engine import TaintEngine
from sastscanner.core.rule_engine import RuleEngine

# ========== SCA Integration ==========
SCA_AVAILABLE = False
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'sca'))
    from sca_simple import scan_dependencies
    SCA_AVAILABLE = True
    print("✅ SCA simple scanner loaded")
except ImportError as e:
    print(f"⚠️ SCA simple scanner not found – SCA disabled (error: {e})")
# =====================================

# ========== Helper: emit finding to TUI ==========
def emit_finding(severity: str, type_: str, file_path: str,
                 start_line: int, end_line: int, description: str,
                 original_code: str = "", fix_suggestion: str = ""):
    findings_file = os.environ.get("SUDOFIX_FINDINGS_FILE")
    if not findings_file:
        return
    try:
        with open(findings_file, "a") as f:
            json.dump({
                "severity": severity,
                "type": type_,
                "file": file_path,
                "start_line": start_line,
                "end_line": end_line,
                "description": description,
                "original_code": original_code,
                "fix_suggestion": fix_suggestion
            }, f)
            f.write("\n")
    except Exception:
        pass
# =================================================

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
    print("\n📦 Running SCA only (using simple scanner)...")
    sca_vulns = []
    try:
        sca_vulns = scan_dependencies(repo_path)
        print(f"✅ SCA found {len(sca_vulns)} vulnerable dependencies")
        if sca_vulns:
            for v in sca_vulns:
                emit_finding(
                    severity=v.get("severity", "MEDIUM"),
                    type_="SCA",
                    file_path=v.get("file_path", "unknown"),
                    start_line=1,
                    end_line=1,
                    description=f"{v['package']} {v['version']} : {v['cve']}",
                    original_code="",
                    fix_suggestion=f"Upgrade {v['package']} to version {v.get('fixed_version', 'latest')}"
                )
            report_lines = ["# SCA Vulnerability Report\n"]
            for v in sca_vulns:
                report_lines.append(
                    f"- **{v['package']}** {v['version']} : {v['cve']} "
                    f"(severity: {v['severity']})"
                )
            sca_text = "\n".join(report_lines)
            print("\n" + sca_text)
            with open("sca_report.md", "w") as f:
                f.write(sca_text)
        else:
            print("No vulnerable dependencies found.")
    except Exception as e:
        print(f"❌ SCA error: {e}")

def run_sast_pipeline(repo_path, command, db, redis_client, sca_vulns=None):
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
        taint_findings = []
        try:
            taint_result = taint_engine.analyze(nodes, language=language)
            # taint_result might be list of dicts or list of objects
            if taint_result:
                for item in taint_result:
                    if isinstance(item, dict):
                        taint_findings.append(item)
                    else:
                        # Convert object to dict if needed
                        taint_findings.append({
                            "severity": getattr(item, "severity", "HIGH"),
                            "line": getattr(item, "line", chunk.get("start_line", 1)),
                            "end_line": getattr(item, "end_line", chunk.get("end_line", 1)),
                            "message": getattr(item, "message", str(item)),
                            "fix_suggestion": getattr(item, "fix_suggestion", "")
                        })
        except Exception as e:
            print("❌ Taint error:", e)

        # Rule engine
        rule_findings = []
        try:
            rule_result = rule_engine.scan(
                chunk,
                context={
                    "language": language,
                    "taint_findings": taint_findings,
                    "taint_vars": getattr(taint_engine, "state", None),
                }
            )
            if rule_result:
                for item in rule_result:
                    if isinstance(item, dict):
                        rule_findings.append(item)
                    else:
                        rule_findings.append({
                            "severity": getattr(item, "severity", "MEDIUM"),
                            "rule_id": getattr(item, "rule_id", "Unknown"),
                            "line": getattr(item, "line", chunk.get("start_line", 1)),
                            "end_line": getattr(item, "end_line", chunk.get("end_line", 1)),
                            "message": getattr(item, "message", str(item)),
                            "fix_suggestion": getattr(item, "fix_suggestion", "")
                        })
        except Exception as e:
            print("❌ Rule engine error:", e)

        # Emit taint findings
        for finding in taint_findings:
            emit_finding(
                severity=finding.get("severity", "HIGH"),
                type_="Taint",
                file_path=file_path,
                start_line=finding.get("line", chunk.get("start_line", 1)),
                end_line=finding.get("end_line", chunk.get("end_line", 1)),
                description=finding.get("message", "Potential tainted data flow"),
                original_code=chunk.get("content", ""),
                fix_suggestion=finding.get("fix_suggestion", "")
            )

        # Emit rule findings
        for finding in rule_findings:
            emit_finding(
                severity=finding.get("severity", "MEDIUM"),
                type_=finding.get("rule_id", "Rule"),
                file_path=file_path,
                start_line=finding.get("line", chunk.get("start_line", 1)),
                end_line=finding.get("end_line", chunk.get("end_line", 1)),
                description=finding.get("message", "Rule violation"),
                original_code=chunk.get("content", ""),
                fix_suggestion=finding.get("fix_suggestion", "")
            )

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

        # LLM step (optional)
        result = None
        if (taint_findings or rule_findings or len(nodes) > 5 or chunk_sca):
            try:
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

    if sca_vulns and command == "review":
        print("\n📦 SCA Findings Summary (from earlier):")
        for v in sca_vulns[:5]:
            print(f"  - {v['package']} {v['version']} : {v['cve']}")

def run_llm(repo_path: str, command: str, mode: str):
    print(f"\n🚀 Starting pipeline | Mode: {mode.upper()} | Command: {command}")

    db = Postgres()
    cache = RedisManager()
    db_conn = db.connect()
    redis_client = cache.connect()
    if not db_conn or not redis_client:
        print("❌ DB/Redis connection failed")
        return

    try:
        if mode == 'sca':
            if not SCA_AVAILABLE:
                print("❌ SCA not available.")
                return
            run_sca_only(repo_path, command, db, redis_client)
            return

        sca_vulns = None
        if mode == 'full' and SCA_AVAILABLE:
            print("\n📦 Running SCA before SAST (simple scanner)...")
            try:
                sca_vulns = scan_dependencies(repo_path)
                print(f"✅ SCA found {len(sca_vulns)} vulnerable dependencies")
            except Exception as e:
                print(f"❌ SCA error (continuing without SCA): {e}")

        run_sast_pipeline(repo_path, command, db, redis_client, sca_vulns)

    except Exception as e:
        print("❌ Pipeline crash:", e)
    finally:
        print("\n🔻 Cleaning up...")
        db_conn.close()
        redis_client.close()
        print("👋 Done")

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

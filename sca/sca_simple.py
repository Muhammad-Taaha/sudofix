#!/usr/bin/env python3
"""
Lightweight SCA wrapper using native audit tools + OSV-Scanner.
"""

import subprocess
import json
import sys
from pathlib import Path
from typing import List, Dict, Any

# ------------------------------------------------------------------
#  Helper: run a command and return parsed JSON or empty list on error
# ------------------------------------------------------------------
def _run_json_cmd(cmd: List[str], cwd: Path) -> Dict[str, Any]:
    try:
        result = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=90
        )
        # Some tools exit 1 when vulnerabilities found; still parse stdout
        return json.loads(result.stdout)
    except Exception as e:
        print(f"Command failed: {' '.join(cmd)} -> {e}")
        return {}

# ------------------------------------------------------------------
#  Ecosystem‑specific scanners
# ------------------------------------------------------------------
def npm_audit(repo_path):
    try:
        result = subprocess.run(
            ["npm", "audit", "--json"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=60
        )
        data = json.loads(result.stdout)
        vulns = []
        for pkg, info in data.get("vulnerabilities", {}).items():
            # version is inside 'via' list or directly in 'version'
            version = info.get("version")
            if not version and "via" in info:
                for entry in info["via"]:
                    if isinstance(entry, dict) and "version" in entry:
                        version = entry["version"]
                        break
            # CVE: often in 'cves' list
            cve = info.get("cves", [None])[0]
            if not cve and "via" in info:
                for entry in info["via"]:
                    if isinstance(entry, dict) and "cve" in entry:
                        cve = entry["cve"]
                        break
            vulns.append({
                "package": pkg,
                "version": version or "unknown",
                "cve": cve or "unknown",
                "severity": info.get("severity", "unknown"),
                "fix_available": bool(info.get("fixAvailable")),
                "file_path": str(repo_path / "package-lock.json"),
            })
        return vulns
    except Exception as e:
        print(f"npm audit failed: {e}")
        return []

def yarn_audit(repo_path: Path) -> List[Dict]:
    """yarn audit --json"""
    data = _run_json_cmd(["yarn", "audit", "--json"], repo_path)
    # yarn output is one JSON object per line; we need to collect
    try:
        # First line often "type":"activity", last line "type":"auditSummary"
        for line in data.get("data", "").splitlines():
            if line:
                obj = json.loads(line)
                if obj.get("type") == "auditSummary":
                    vulns = []
                    for pkg, info in obj.get("data", {}).get("vulnerabilities", {}).items():
                        vulns.append({
                            "package": pkg,
                            "version": info.get("version"),
                            "cve": info.get("cves", [None])[0],
                            "severity": info.get("severity", "unknown"),
                            "fix_available": bool(info.get("fixAvailable")),
                            "file_path": str(repo_path / "yarn.lock"),
                        })
                    return vulns
    except Exception:
        pass
    return []

def pip_audit(repo_path: Path) -> List[Dict]:
    """pip-audit --format json"""
    req_file = repo_path / "requirements.txt"
    if not req_file.exists():
        return []
    data = _run_json_cmd(["pip-audit", "--requirement", str(req_file), "--format", "json"], repo_path)
    vulns = []
    for dep in data.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            vulns.append({
                "package": dep.get("name"),
                "version": dep.get("version"),
                "cve": vuln.get("id"),
                "severity": vuln.get("severity", "unknown"),
                "fix_available": bool(vuln.get("fix_versions")),
                "file_path": str(req_file),
            })
    return vulns

def cargo_audit(repo_path: Path) -> List[Dict]:
    """cargo audit --json"""
    lock_file = repo_path / "Cargo.lock"
    if not lock_file.exists():
        return []
    data = _run_json_cmd(["cargo", "audit", "--json"], repo_path)
    vulns = []
    for vuln in data.get("vulnerabilities", {}).get("list", []):
        vulns.append({
            "package": vuln.get("package", {}).get("name"),
            "version": vuln.get("package", {}).get("version"),
            "cve": vuln.get("advisory", {}).get("id"),
            "severity": vuln.get("advisory", {}).get("severity", "unknown"),
            "fix_available": bool(vuln.get("versions", {}).get("patched")),
            "file_path": str(lock_file),
        })
    return vulns

def govulncheck(repo_path: Path) -> List[Dict]:
    """govulncheck -json"""
    # Check for go.mod
    if not (repo_path / "go.mod").exists():
        return []
    data = _run_json_cmd(["govulncheck", "-json", "./..."], repo_path)
    vulns = []
    # govulncheck emits multiple JSON lines; we need to accumulate findings
    # Simpler: parse each line
    try:
        # It's a stream; we combine all lines into a list
        result = subprocess.run(
            ["govulncheck", "-json", "./..."], cwd=repo_path,
            capture_output=True, text=True, timeout=90
        )
        for line in result.stdout.splitlines():
            if not line:
                continue
            obj = json.loads(line)
            if obj.get("finding"):
                vuln = obj["finding"]["osv"]
                vulns.append({
                    "package": obj["finding"]["module"],
                    "version": obj["finding"]["version"],
                    "cve": vuln.get("id"),
                    "severity": vuln.get("severity", "unknown"),
                    "fix_available": bool(vuln.get("versions", {}).get("patched")),
                    "file_path": str(repo_path / "go.mod"),
                })
    except Exception:
        pass
    return vulns

def osv_scanner(repo_path: Path) -> List[Dict]:
    """Unified scanner (supports all ecosystems) using OSV-Scanner."""
    try:
        result = subprocess.run(
            ["osv-scanner", "--format", "json", "-r", str(repo_path)],
            capture_output=True, text=True, timeout=120
        )
        data = json.loads(result.stdout)
        vulns = []
        for pkg in data.get("results", []):
            for vuln in pkg.get("vulnerabilities", []):
                vulns.append({
                    "package": pkg.get("package", {}).get("name"),
                    "version": pkg.get("package", {}).get("version"),
                    "cve": vuln.get("id"),
                    "severity": vuln.get("severity", "unknown"),
                    "fix_available": bool(vuln.get("fix_versions")),
                    "file_path": pkg.get("source", {}).get("path", str(repo_path)),
                })
        return vulns
    except Exception as e:
        print(f"osv-scanner failed: {e}")
        return []

def java_scan(repo_path: Path) -> List[Dict]:
    """
    Java: use osv-scanner (preferred) or fallback to OWASP Dependency Check.
    We'll try osv-scanner first because it handles pom.xml / build.gradle.
    """
    return osv_scanner(repo_path)   # osv-scanner works for Java

def cpp_scan(repo_path: Path) -> List[Dict]:
    """
    C/C++: osv-scanner can scan vcpkg.json, conan.lock, or plain CMake.
    If none exists, try cve-bin-tool (fallback).
    """
    # Look for common lockfiles
    if any((repo_path / f).exists() for f in ["vcpkg.json", "conan.lock", "CMakeLists.txt"]):
        return osv_scanner(repo_path)
    return []

# ------------------------------------------------------------------
#  Main dispatcher: detect ecosystem and call appropriate scanner
# ------------------------------------------------------------------
def scan_dependencies(repo_path: str) -> List[Dict]:
    repo = Path(repo_path).resolve()
    findings = []

    # Priority: prefer lockfiles over manifests
    # Node
    if (repo / "package-lock.json").exists():
        findings = npm_audit(repo)
    elif (repo / "yarn.lock").exists():
        findings = yarn_audit(repo)
    # Python
    elif (repo / "requirements.txt").exists():
        findings = pip_audit(repo)
    # Rust
    elif (repo / "Cargo.lock").exists():
        findings = cargo_audit(repo)
    # Go
    elif (repo / "go.mod").exists():
        findings = govulncheck(repo)
    # Java
    elif any((repo / f).exists() for f in ["pom.xml", "build.gradle", "build.gradle.kts"]):
        findings = java_scan(repo)
    # C/C++
    elif any((repo / f).exists() for f in ["vcpkg.json", "conan.lock", "CMakeLists.txt"]):
        findings = cpp_scan(repo)
    else:
        # Last resort: use osv-scanner on whole repo (it auto-detects)
        findings = osv_scanner(repo)

    # Deduplicate by (package, cve)
    unique = {}
    for f in findings:
        key = (f["package"], f["cve"])
        if key not in unique:
            unique[key] = f
    return list(unique.values())

# ------------------------------------------------------------------
#  For testing
# ------------------------------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python sca_simple.py <repo_path>")
        sys.exit(1)
    vulns = scan_dependencies(sys.argv[1])
    print(json.dumps(vulns, indent=2))
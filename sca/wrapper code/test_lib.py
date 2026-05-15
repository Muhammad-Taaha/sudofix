import subprocess
import json
import os
from collections import defaultdict
from typing import List, Dict, Any, Optional


class RepoIntelligenceEngine:
    """
    Production-grade repository intelligence engine using ScanCode Toolkit.
    """

    def __init__(
        self,
        scancode_path: str,
        exclude_paths: Optional[List[str]] = None,
        include_paths: Optional[List[str]] = None,
        output_file: str = "scan.json"
    ):
        self.scancode_path = scancode_path
        self.exclude_paths = exclude_paths or []
        self.include_paths = include_paths or []
        self.output_file = output_file

    # =========================================================
    # 1. SCANCODE EXECUTION LAYER
    # =========================================================
    def run_scancode(self, repo_path: str) -> Dict[str, Any]:
        if not os.path.exists(repo_path):
            raise FileNotFoundError(f"Repo not found: {repo_path}")

        cmd = [
            self.scancode_path,
            "--license",
            "--copyright",
            "--package",
            "--verbose",
            "--json",
            self.output_file,
            repo_path
        ]

        # Apply exclusions
        for path in self.exclude_paths:
            cmd.extend(["--ignore", path])

        # Apply inclusions (optional override)
        for path in self.include_paths:
            cmd.extend(["--include", path])

        print(f"\n🚀 Running ScanCode on: {repo_path}")
        subprocess.run(cmd, check=True)

        with open(self.output_file, "r", encoding="utf-8") as f:
            return json.load(f)

    # =========================================================
    # 2. STRUCTURAL ANALYSIS LAYER
    # =========================================================
    def analyze_structure(self, data: Dict[str, Any]) -> Dict[str, Any]:
        files = data.get("files", [])

        structure = {
            "total_files": len(files),
            "file_types": defaultdict(int),
            "licenses": set(),
            "packages": set(),
            "copyrights": [],
        }

        for f in files:
            path = f.get("path", "")

            # file extension grouping
            ext = os.path.splitext(path)[1]
            structure["file_types"][ext] += 1

            # licenses
            for lic in f.get("licenses", []):
                if lic.get("key"):
                    structure["licenses"].add(lic["key"])

            # packages
            for pkg in f.get("packages", []):
                if pkg.get("name"):
                    structure["packages"].add(pkg["name"])

            # copyrights
            for cr in f.get("copyrights", []):
                if cr.get("value"):
                    structure["copyrights"].append(cr["value"])

        return {
            "total_files": structure["total_files"],
            "file_types": dict(structure["file_types"]),
            "licenses": list(structure["licenses"]),
            "packages": list(structure["packages"]),
            "copyrights": structure["copyrights"]
        }

    # =========================================================
    # 3. SECURITY / RISK ENGINE
    # =========================================================
    def risk_analysis(self, structure: Dict[str, Any]) -> Dict[str, Any]:
        risk_score = 0
        issues = []

        licenses = " ".join(structure["licenses"]).lower()
        packages = structure["packages"]

        # license risk
        if "gpl" in licenses:
            risk_score += 4
            issues.append("GPL license detected (copyleft risk)")

        if "unknown" in licenses or len(structure["licenses"]) == 0:
            risk_score += 3
            issues.append("Unknown or missing license info")

        # dependency risk
        if len(packages) > 50:
            risk_score += 2
            issues.append("High dependency count (potential complexity risk)")

        return {
            "risk_score": min(risk_score, 10),
            "issues": issues
        }

    # =========================================================
    # 4. ARCHITECTURE INFERENCE ENGINE
    # =========================================================
    def infer_architecture(self, structure: Dict[str, Any]) -> Dict[str, Any]:
        file_types = structure["file_types"]

        dominant = sorted(file_types.items(), key=lambda x: -x[1])[:5]

        if ".py" in file_types:
            arch = "Python-based backend or modular system"
        elif ".js" in file_types:
            arch = "JavaScript/Node.js application"
        elif ".java" in file_types:
            arch = "Java enterprise-style application"
        else:
            arch = "Mixed / polyglot system"

        return {
            "architecture_guess": arch,
            "dominant_file_types": dominant
        }

    # =========================================================
    # 5. FINAL REPORT GENERATION
    # =========================================================
    def generate_report(self, repo_path: str) -> Dict[str, Any]:
        raw = self.run_scancode(repo_path)
        structure = self.analyze_structure(raw)
        risk = self.risk_analysis(structure)
        architecture = self.infer_architecture(structure)

        return {
            "repo_summary": {
                "total_files": structure["total_files"],
                "licenses": structure["licenses"],
                "packages": structure["packages"]
            },
            "architecture": architecture,
            "security": risk,
            "file_distribution": structure["file_types"],
            "sample_copyrights": structure["copyrights"][:10]
        }

    # =========================================================
    # 6. HUMAN-READABLE OUTPUT
    # =========================================================
    def print_report(self, report: Dict[str, Any]) -> None:
        print("\n" + "=" * 50)
        print("📊 REPO INTELLIGENCE REPORT")
        print("=" * 50)

        print("\n📁 Total Files:", report["repo_summary"]["total_files"])
        print("📜 Licenses:", report["repo_summary"]["licenses"])
        print("📦 Packages:", report["repo_summary"]["packages"])

        print("\n🏗 Architecture:")
        print(report["architecture"]["architecture_guess"])

        print("\n⚠️ Risk Score:", report["security"]["risk_score"])
        for issue in report["security"]["issues"]:
            print(" -", issue)

        print("\n📂 File Distribution:")
        for k, v in report["file_distribution"].items():
            print(f" {k}: {v}")

        print("\n© Sample Copyrights:")
        for c in report["sample_copyrights"]:
            print(" -", c)


# =========================================================
# ENTRY POINT
# =========================================================
if __name__ == "__main__":

    EXCLUDE_PATHS = [
        "node_modules",
        "venv",
        ".git",
        "dist",
        "build",
        "__pycache__",
        "scancode_wrapper",
        "scancode-toolkit"
    ]

    ENGINE = RepoIntelligenceEngine(
        scancode_path=r"D:\HACKATHON PROJECT\repo-llm\scancode-toolkit\scancode.bat",
        exclude_paths=EXCLUDE_PATHS
    )

    REPO_PATH = r"D:\HACKATHON PROJECT\repo-llm\diagrams"

    report = ENGINE.generate_report(REPO_PATH)
    ENGINE.print_report(report)
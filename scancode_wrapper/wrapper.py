import subprocess
import json
import os
from typing import Dict, Any


class ScanCodeAnalyzer:
    def __init__(self, scancode_path: str = "scancode"):
        self.scancode_path = scancode_path

    def scan(self, target_path: str, output_file: str = "scancode_output.json") -> Dict[str, Any]:
        """
        Run ScanCode on a file or repo and return parsed JSON.
        """
        if not os.path.exists(target_path):
            raise FileNotFoundError(f"Path not found: {target_path}")

        command = [
            self.scancode_path,
            "--license",
            "--copyright",
            "--json",
            output_file,
            target_path
        ]

        try:
            print(f"🚀 Running ScanCode on: {target_path}")
            subprocess.run(command, check=True)

            with open(output_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            return data

        except subprocess.CalledProcessError as e:
            print(f"❌ ScanCode execution failed: {e}")
            return {}

    def generate_report(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract rule-based insights from ScanCode output.
        """
        report = {
            "total_files": 0,
            "licenses": set(),
            "copyrights": [],
            "files_with_issues": []
        }

        files = scan_data.get("files", [])

        report["total_files"] = len(files)

        for file in files:
            path = file.get("path")

            # Licenses
            for lic in file.get("licenses", []):
                report["licenses"].add(lic.get("key"))

            # Copyrights
            for cr in file.get("copyrights", []):
                report["copyrights"].append({
                    "file": path,
                    "statement": cr.get("value")
                })

            # Flag risky files
            if file.get("licenses"):
                report["files_with_issues"].append(path)

        # Convert set → list for JSON
        report["licenses"] = list(report["licenses"])

        return report
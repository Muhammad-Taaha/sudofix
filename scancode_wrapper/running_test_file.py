# import subprocess
# import json
# import os
# import tempfile
# import logging

# logger = logging.getLogger(__name__)

# SCAODE_IMAGE = "nexb/scancode-toolkit:32.0.0"

# def scan_target_directory(target_path: str) -> dict:
#     """
#     Calls ScanCode via Docker subprocess. 
#     Returns parsed JSON. Zero coupling to ScanCode internals.
#     """
#     abs_target = os.path.abspath(target_path)
#     if not os.path.isdir(abs_target):
#         raise ValueError(f"Target path is not a directory: {abs_target}")

#     with tempfile.TemporaryDirectory() as tmp_dir:
#         out_json = os.path.join(tmp_dir, "scan_result.json")
        
#         cmd = [
#             "docker", "run", "--rm",
#             "-v", f"{abs_target}:/scan:ro",
#             "-v", f"{tmp_dir}:/output",
#             "--cpus", "2",
#             "--memory", "2g",
#             SCAODE_IMAGE,
#             "--license", "--copyright", "--email", "--url", "--info",
#             "--json", "/output/scan_result.json",
#             "--only-findings",
#             "--strip-root",
#             "--processes", "2",
#             "--ignore", "*.git/*",
#             "--ignore", "node_modules/*",
#             "--ignore", "__pycache__/*",
#             "--ignore", ".venv/*",
#             "/scan"
#         ]

#         try:
#             subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
#         except subprocess.TimeoutExpired:
#             logger.error("ScanCode timed out. Check target size or increase timeout.")
#             raise
#         except subprocess.CalledProcessError as e:
#             logger.error(f"ScanCode failed: {e.stderr}")
#             raise

#         with open(out_json, "r", encoding="utf-8") as f:
#             return json.load(f)










"""
run_scancode.py

Simple configurable ScanCode runner for a SINGLE file.

Modify only:
1. SCANCODE_PATH
2. TARGET_FILE
3. OUTPUT_JSON

Then run:
    python run_scancode.py
"""

import subprocess
import time
from pathlib import Path


# =====================================================
# CONFIGURATION
# =====================================================

# Path to scancode.bat
SCANCODE_PATH = r"D:\HACKATHON PROJECT\repo-llm\scancode-toolkit\scancode.bat"

# File you want to scan
TARGET_FILE = r"D:\HACKATHON PROJECT\repo-llm\Testing_files_for_scancode\huge_test_file_500.py"
# Output JSON
OUTPUT_JSON = r"D:\HACKATHON PROJECT\repo-llm\Testing_files_for_scancode\result.json"


# =====================================================
# VALIDATION
# =====================================================

if not Path(SCANCODE_PATH).exists():
    raise FileNotFoundError(f"ScanCode not found:\n{SCANCODE_PATH}")

if not Path(TARGET_FILE).exists():
    raise FileNotFoundError(f"Target file not found:\n{TARGET_FILE}")


# =====================================================
# COMMAND
# =====================================================

cmd = [
    SCANCODE_PATH,

    "--license",
    "--verbose",
    "--json",
    OUTPUT_JSON,

    TARGET_FILE
]


# =====================================================
# RUN
# =====================================================

print("\nStarting ScanCode scan...\n")

start = time.perf_counter()

try:

    result = subprocess.run(
        cmd,
        check=True,
        text=True,
    )

    end = time.perf_counter()

    print("Scan completed successfully.\n")

    print(f"Time Taken: {end - start:.2f} sec")

    print(f"\nOutput JSON:\n{OUTPUT_JSON}")

except subprocess.CalledProcessError as e:

    print("\nScan failed.\n")

    print("STDOUT:")
    print(e.stdout)

    print("\nSTDERR:")
    print(e.stderr)
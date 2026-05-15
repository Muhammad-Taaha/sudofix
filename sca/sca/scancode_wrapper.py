"""
Minimal scancode CLI wrapper – used only for license and package scans on file lists.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
from pathlib import Path
from typing import Dict, Optional, Tuple, Any


def _get_executable(scancode_dir: Optional[str] = None) -> str:
    exe = "scancode.bat" if platform.system() == "Windows" else "scancode"
    if scancode_dir:
        return str(Path(scancode_dir) / exe)
    return exe


def run_scan(
    file_list: list[str],
    output_file: str,
    scan_type: str,  # "license" or "package"
    *,
    timeout: int = 120,
    processes: int = 4,
    quiet: bool = True,
    scancode_dir: Optional[str] = None,
    process_timeout: int = 600,
    cwd: Optional[str] = None,
) -> Tuple[str, Dict[str, Any]]:
    """
    Scan a list of file paths and return (raw_json_string, parsed_dict).

    Parameters
    ----------
    file_list   : relative paths (preferred) – must be relative to `cwd`.
    output_file : path to write the JSON result.
    scan_type   : "license" or "package".
    timeout     : per‑file timeout in seconds.
    processes   : number of parallel workers.
    quiet       : suppress progress output.
    process_timeout : subprocess timeout in seconds.
    cwd         : working directory in which scancode will be executed.
                  All `file_list` paths must be relative to this directory.

    Raises
    ------
    RuntimeError if scancode returns non‑zero exit code.
    FileNotFoundError if output file is missing after scan.
    """
    exe = _get_executable(scancode_dir)
    cmd = [exe, f"--{scan_type}"]
    cmd += ["--json", output_file]
    cmd += ["-n", str(processes), "--timeout", str(timeout)]
    if quiet:
        cmd.append("--quiet")
    cmd.extend(file_list)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=process_timeout,
        cwd=cwd,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"ScanCode exited with code {result.returncode}.\n"
            f"Command: {' '.join(cmd)}\n"
            f"Stderr:\n{result.stderr}"
        )

    if not os.path.exists(output_file):
        raise FileNotFoundError(f"Expected output file not found: {output_file}")

    with open(output_file, "r", encoding="utf-8") as f:
        raw = f.read()
    parsed = json.loads(raw)
    return raw, parsed
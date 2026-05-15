"""
scancode_wrapper.py
===================
Cross-platform Python wrapper for the scancode-toolkit CLI.

Supports Windows (scancode.bat), Linux, and macOS (scancode).
Every public function returns a (raw, parsed) tuple:
  - raw    : the JSON string read from the output file (str)
  - parsed : the decoded Python dict, or None for non-JSON formats

Requires: Python 3.9+  |  scancode-toolkit installed and accessible.

Usage
-----
    from scancode_wrapper import scan_license, scan_full, extract_licenses

    raw, parsed = scan_license(
        input_path="./my_repo",
        output_file="results.json",
        license_score=70,
        processes=4,
    )
    for detection in extract_licenses(parsed):
        print(detection["license_expression"])
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
from pathlib import Path
from typing import Optional


# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

def _get_executable(scancode_dir: Optional[str] = None) -> str:
    """
    Return the correct scancode executable for the current OS.

    Parameters
    ----------
    scancode_dir : str, optional
        Absolute path to the directory that contains scancode / scancode.bat.
        If None, the executable is expected to be on PATH.

    Returns
    -------
    str
        Full path to the executable, or just the executable name if on PATH.
    """
    exe = "scancode.bat" if platform.system() == "Windows" else "scancode"
    if scancode_dir:
        return str(Path(scancode_dir) / exe)
    return exe


def _build_output_flags(fmt: str, out_file: str) -> list[str]:
    """
    Map a friendly format name to the correct scancode CLI flag pair.

    Supported formats
    -----------------
    json, json-pp, json-lines, yaml, csv, html,
    cyclonedx, cyclonedx-xml, spdx-rdf, spdx-tv, debian

    Parameters
    ----------
    fmt      : output format name (see above)
    out_file : path to write the scan output to

    Returns
    -------
    list[str]
        Two-element list: [flag, out_file]
    """
    _map: dict[str, str] = {
        "json":          "--json",
        "json-pp":       "--json-pp",
        "json-lines":    "--json-lines",
        "yaml":          "--yaml",
        "csv":           "--csv",
        "html":          "--html",
        "cyclonedx":     "--cyclonedx",
        "cyclonedx-xml": "--cyclonedx-xml",
        "spdx-rdf":      "--spdx-rdf",
        "spdx-tv":       "--spdx-tv",
        "debian":        "--debian",
    }
    flag = _map.get(fmt, "--json")
    return [flag, out_file]


def _run_subprocess(cmd: list[str], process_timeout: int = 600) -> tuple[str, str, int]:
    """
    Execute a subprocess command and capture its output.

    Parameters
    ----------
    cmd             : full command list to pass to subprocess.run
    process_timeout : seconds before the Python subprocess.run call times out
                      (separate from scancode's per-file --timeout flag)

    Returns
    -------
    tuple[str, str, int]
        (stdout, stderr, returncode)
    """
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=process_timeout,
    )
    return result.stdout, result.stderr, result.returncode


def _execute(
    cmd: list[str],
    out_file: str,
    fmt: str,
    process_timeout: int = 600,
) -> tuple[str, Optional[dict]]:
    """
    Run a scancode command, read the output file, and return results.

    Parameters
    ----------
    cmd             : fully-built command list
    out_file        : path to the output file scancode will write
    fmt             : output format string (e.g. "json", "json-pp")
    process_timeout : seconds before the Python-level subprocess times out

    Returns
    -------
    tuple[str, Optional[dict]]
        (raw_string, parsed_dict)
        parsed_dict is None when the output format is not JSON-based.

    Raises
    ------
    RuntimeError
        If scancode exits with a non-zero return code.
    FileNotFoundError
        If the output file was not created after the scan.
    """
    stdout, stderr, code = _run_subprocess(cmd, process_timeout)

    if code != 0:
        raise RuntimeError(
            f"ScanCode exited with code {code}.\n"
            f"Command: {' '.join(cmd)}\n"
            f"Stderr:\n{stderr}"
        )

    json_formats = {"json", "json-pp", "json-lines"}
    raw = ""
    parsed: Optional[dict] = None

    if fmt in json_formats:
        if not os.path.exists(out_file):
            raise FileNotFoundError(
                f"Expected output file not found: {out_file}\n"
                f"Stderr: {stderr}"
            )
        with open(out_file, "r", encoding="utf-8") as f:
            raw = f.read()

        if fmt == "json-lines":
            # NDJSON: each line is a JSON object; return list under "lines" key
            lines = [json.loads(ln) for ln in raw.splitlines() if ln.strip()]
            parsed = {"lines": lines}
        else:
            parsed = json.loads(raw)

    return raw, parsed


# ──────────────────────────────────────────────────────────────────────────────
# Primary scan functions
# ──────────────────────────────────────────────────────────────────────────────

def scan_license(
    input_path: str,
    output_file: str,
    *,
    # --- scan options ---
    output_format: str = "json",
    license_score: int = 0,
    license_text: bool = False,
    license_text_diagnostics: bool = False,
    license_diagnostics: bool = False,
    unknown_licenses: bool = False,
    # --- output filters ---
    only_findings: bool = False,
    ignore_author: Optional[str] = None,
    ignore_copyright_holder: Optional[str] = None,
    # --- output control ---
    full_root: bool = False,
    strip_root: bool = False,
    # --- pre-scan ---
    ignore: Optional[list[str]] = None,
    include: Optional[list[str]] = None,
    max_depth: int = 0,
    # --- post-scan ---
    classify: bool = False,
    filter_clues: bool = False,
    license_references: bool = False,
    license_clarity_score: bool = False,
    license_policy: Optional[str] = None,
    tallies: bool = False,
    tallies_by_facet: bool = False,
    tallies_key_files: bool = False,
    tallies_with_details: bool = False,
    summary: bool = False,
    todo: bool = False,
    mark_source: bool = False,
    # --- core ---
    processes: int = -1,
    timeout: int = 120,
    max_in_memory: int = 10000,
    quiet: bool = False,
    # --- wrapper ---
    scancode_dir: Optional[str] = None,
    process_timeout: int = 600,
) -> tuple[str, Optional[dict]]:
    """
    Scan <input_path> for licenses only.

    Parameters
    ----------
    input_path      : file or directory to scan
    output_file     : path where scancode writes results
    output_format   : one of json | json-pp | json-lines | yaml | csv | html |
                      cyclonedx | cyclonedx-xml | spdx-rdf | spdx-tv | debian
    license_score   : discard matches below this 0-100 confidence score
    license_text    : include matched license text in results
    license_text_diagnostics : highlight unmatched words in license text
    license_diagnostics      : include post-processing diagnostic details
    unknown_licenses         : (experimental) detect unknown license patterns
    only_findings   : omit files with no detections from output
    ignore_author   : regex — ignore files whose author matches this pattern
    ignore_copyright_holder  : regex — ignore files whose copyright holder matches
    full_root       : report absolute paths
    strip_root      : strip the root directory segment from all paths
    ignore          : list of glob patterns to exclude from the scan
    include         : list of glob patterns to restrict the scan to
    max_depth       : maximum subdirectory depth to descend (0 = unlimited)
    classify        : classify files as legal / readme / test / etc.
    filter_clues    : remove clues already covered by full detections
    license_references      : include full license rule reference data
    license_clarity_score   : compute a codebase-level clarity score
    license_policy  : path to a license policy YAML file
    tallies         : compute per-license/copyright tallies at codebase level
    tallies_by_facet        : group tallies by facet
    tallies_key_files       : tally key top-level files only
    tallies_with_details    : tally with intermediate file-level details
    summary         : add declared-origin summary to the codebase attribute
    todo            : list ambiguous detections that need manual review
    mark_source     : flag directories with >90% source files
    processes       : number of parallel workers (-1 = disable threading,
                      0 = no parallelism, N = N workers)
    timeout         : per-file scan timeout in seconds (default 120)
    max_in_memory   : max file details kept in RAM (0 = unlimited, -1 = disk only)
    quiet           : suppress progress bar and summary output
    scancode_dir    : path to scancode install directory (None = use PATH)
    process_timeout : Python-level subprocess timeout in seconds

    Returns
    -------
    tuple[str, Optional[dict]]
        (raw_json_string, parsed_dict)
    """
    exe = _get_executable(scancode_dir)
    cmd = [exe, "--license"]

    if license_score > 0:
        cmd += ["--license-score", str(license_score)]
    if license_text:
        cmd.append("--license-text")
    if license_text_diagnostics:
        cmd.append("--license-text-diagnostics")
    if license_diagnostics:
        cmd.append("--license-diagnostics")
    if unknown_licenses:
        cmd.append("--unknown-licenses")

    cmd += _build_output_flags(output_format, output_file)

    if only_findings:
        cmd.append("--only-findings")
    if ignore_author:
        cmd += ["--ignore-author", ignore_author]
    if ignore_copyright_holder:
        cmd += ["--ignore-copyright-holder", ignore_copyright_holder]
    if full_root:
        cmd.append("--full-root")
    if strip_root:
        cmd.append("--strip-root")

    for pat in (ignore or []):
        cmd += ["--ignore", pat]
    for pat in (include or []):
        cmd += ["--include", pat]
    if max_depth > 0:
        cmd += ["--max-depth", str(max_depth)]

    if classify:
        cmd.append("--classify")
    if filter_clues:
        cmd.append("--filter-clues")
    if license_references:
        cmd.append("--license-references")
    if license_clarity_score:
        cmd.append("--license-clarity-score")
    if license_policy:
        cmd += ["--license-policy", license_policy]
    if tallies:
        cmd.append("--tallies")
    if tallies_by_facet:
        cmd.append("--tallies-by-facet")
    if tallies_key_files:
        cmd.append("--tallies-key-files")
    if tallies_with_details:
        cmd.append("--tallies-with-details")
    if summary:
        cmd.append("--summary")
    if todo:
        cmd.append("--todo")
    if mark_source:
        cmd.append("--mark-source")

    cmd += ["-n", str(processes), "--timeout", str(timeout)]
    cmd += ["--max-in-memory", str(max_in_memory)]
    if quiet:
        cmd.append("--quiet")

    cmd.append(input_path)
    return _execute(cmd, output_file, output_format, process_timeout)


def scan_package(
    input_path: str,
    output_file: str,
    *,
    output_format: str = "json",
    only_findings: bool = False,
    full_root: bool = False,
    strip_root: bool = False,
    ignore: Optional[list[str]] = None,
    include: Optional[list[str]] = None,
    max_depth: int = 0,
    classify: bool = False,
    consolidate: bool = False,
    tallies: bool = False,
    summary: bool = False,
    processes: int = -1,
    timeout: int = 120,
    max_in_memory: int = 10000,
    quiet: bool = False,
    scancode_dir: Optional[str] = None,
    process_timeout: int = 600,
) -> tuple[str, Optional[dict]]:
    """
    Scan <input_path> for application package and dependency manifests,
    lockfiles, and related data (e.g. setup.py, package.json, requirements.txt).

    Parameters
    ----------
    consolidate : group results by package or license + copyright holder
                  (requires copyright + license flags; use scan_full for that)

    All other parameters are identical to scan_license().
    """
    exe = _get_executable(scancode_dir)
    cmd = [exe, "--package"]

    cmd += _build_output_flags(output_format, output_file)

    if only_findings:
        cmd.append("--only-findings")
    if full_root:
        cmd.append("--full-root")
    if strip_root:
        cmd.append("--strip-root")
    for pat in (ignore or []):
        cmd += ["--ignore", pat]
    for pat in (include or []):
        cmd += ["--include", pat]
    if max_depth > 0:
        cmd += ["--max-depth", str(max_depth)]

    if classify:
        cmd.append("--classify")
    if consolidate:
        cmd.append("--consolidate")
    if tallies:
        cmd.append("--tallies")
    if summary:
        cmd.append("--summary")

    cmd += ["-n", str(processes), "--timeout", str(timeout)]
    cmd += ["--max-in-memory", str(max_in_memory)]
    if quiet:
        cmd.append("--quiet")

    cmd.append(input_path)
    return _execute(cmd, output_file, output_format, process_timeout)


def scan_copyright(
    input_path: str,
    output_file: str,
    *,
    output_format: str = "json",
    only_findings: bool = False,
    ignore_author: Optional[str] = None,
    ignore_copyright_holder: Optional[str] = None,
    full_root: bool = False,
    strip_root: bool = False,
    ignore: Optional[list[str]] = None,
    include: Optional[list[str]] = None,
    max_depth: int = 0,
    classify: bool = False,
    tallies: bool = False,
    summary: bool = False,
    processes: int = -1,
    timeout: int = 120,
    max_in_memory: int = 10000,
    quiet: bool = False,
    scancode_dir: Optional[str] = None,
    process_timeout: int = 600,
) -> tuple[str, Optional[dict]]:
    """
    Scan <input_path> for copyright statements.

    All parameters are identical to scan_license() where applicable.
    """
    exe = _get_executable(scancode_dir)
    cmd = [exe, "--copyright"]

    cmd += _build_output_flags(output_format, output_file)

    if only_findings:
        cmd.append("--only-findings")
    if ignore_author:
        cmd += ["--ignore-author", ignore_author]
    if ignore_copyright_holder:
        cmd += ["--ignore-copyright-holder", ignore_copyright_holder]
    if full_root:
        cmd.append("--full-root")
    if strip_root:
        cmd.append("--strip-root")
    for pat in (ignore or []):
        cmd += ["--ignore", pat]
    for pat in (include or []):
        cmd += ["--include", pat]
    if max_depth > 0:
        cmd += ["--max-depth", str(max_depth)]

    if classify:
        cmd.append("--classify")
    if tallies:
        cmd.append("--tallies")
    if summary:
        cmd.append("--summary")

    cmd += ["-n", str(processes), "--timeout", str(timeout)]
    cmd += ["--max-in-memory", str(max_in_memory)]
    if quiet:
        cmd.append("--quiet")

    cmd.append(input_path)
    return _execute(cmd, output_file, output_format, process_timeout)


def scan_system_package(
    input_path: str,
    output_file: str,
    *,
    output_format: str = "json",
    only_findings: bool = False,
    processes: int = -1,
    timeout: int = 120,
    quiet: bool = False,
    scancode_dir: Optional[str] = None,
    process_timeout: int = 600,
) -> tuple[str, Optional[dict]]:
    """
    Scan for installed system package databases
    (e.g. dpkg status files, RPM databases).
    """
    exe = _get_executable(scancode_dir)
    cmd = [exe, "--system-package"]
    cmd += _build_output_flags(output_format, output_file)
    if only_findings:
        cmd.append("--only-findings")
    cmd += ["-n", str(processes), "--timeout", str(timeout)]
    if quiet:
        cmd.append("--quiet")
    cmd.append(input_path)
    return _execute(cmd, output_file, output_format, process_timeout)


def scan_package_in_compiled(
    input_path: str,
    output_file: str,
    *,
    output_format: str = "json",
    processes: int = -1,
    timeout: int = 120,
    quiet: bool = False,
    scancode_dir: Optional[str] = None,
    process_timeout: int = 600,
) -> tuple[str, Optional[dict]]:
    """
    Scan compiled binaries for embedded package and dependency data.
    Currently supported: Go binaries, Rust binaries.
    """
    exe = _get_executable(scancode_dir)
    cmd = [exe, "--package-in-compiled"]
    cmd += _build_output_flags(output_format, output_file)
    cmd += ["-n", str(processes), "--timeout", str(timeout)]
    if quiet:
        cmd.append("--quiet")
    cmd.append(input_path)
    return _execute(cmd, output_file, output_format, process_timeout)


def scan_package_only(
    input_path: str,
    output_file: str,
    *,
    output_format: str = "json",
    processes: int = -1,
    timeout: int = 120,
    quiet: bool = False,
    scancode_dir: Optional[str] = None,
    process_timeout: int = 600,
) -> tuple[str, Optional[dict]]:
    """
    Scan for package data only — skips license and copyright detection.
    Faster than scan_package() when you only need dependency manifests.
    """
    exe = _get_executable(scancode_dir)
    cmd = [exe, "--package-only"]
    cmd += _build_output_flags(output_format, output_file)
    cmd += ["-n", str(processes), "--timeout", str(timeout)]
    if quiet:
        cmd.append("--quiet")
    cmd.append(input_path)
    return _execute(cmd, output_file, output_format, process_timeout)


def scan_info(
    input_path: str,
    output_file: str,
    *,
    output_format: str = "json",
    generated: bool = False,
    full_root: bool = False,
    strip_root: bool = False,
    ignore: Optional[list[str]] = None,
    max_depth: int = 0,
    mark_source: bool = False,
    processes: int = -1,
    timeout: int = 120,
    quiet: bool = False,
    scancode_dir: Optional[str] = None,
    process_timeout: int = 600,
) -> tuple[str, Optional[dict]]:
    """
    Scan for file information: size, MD5/SHA1/SHA256 checksums, MIME type,
    programming language, and whether the file is binary or text.

    Parameters
    ----------
    generated : also classify auto-generated code files with a flag
    """
    exe = _get_executable(scancode_dir)
    cmd = [exe, "--info"]
    if generated:
        cmd.append("--generated")
    cmd += _build_output_flags(output_format, output_file)
    if full_root:
        cmd.append("--full-root")
    if strip_root:
        cmd.append("--strip-root")
    for pat in (ignore or []):
        cmd += ["--ignore", pat]
    if max_depth > 0:
        cmd += ["--max-depth", str(max_depth)]
    if mark_source:
        cmd.append("--mark-source")
    cmd += ["-n", str(processes), "--timeout", str(timeout)]
    if quiet:
        cmd.append("--quiet")
    cmd.append(input_path)
    return _execute(cmd, output_file, output_format, process_timeout)


def scan_email(
    input_path: str,
    output_file: str,
    *,
    output_format: str = "json",
    max_email: int = 50,
    only_findings: bool = False,
    ignore: Optional[list[str]] = None,
    processes: int = -1,
    timeout: int = 120,
    quiet: bool = False,
    scancode_dir: Optional[str] = None,
    process_timeout: int = 600,
) -> tuple[str, Optional[dict]]:
    """
    Scan <input_path> for email addresses.

    Parameters
    ----------
    max_email : maximum number of emails to report per file (0 = no limit)
    """
    exe = _get_executable(scancode_dir)
    cmd = [exe, "--email", "--max-email", str(max_email)]
    cmd += _build_output_flags(output_format, output_file)
    if only_findings:
        cmd.append("--only-findings")
    for pat in (ignore or []):
        cmd += ["--ignore", pat]
    cmd += ["-n", str(processes), "--timeout", str(timeout)]
    if quiet:
        cmd.append("--quiet")
    cmd.append(input_path)
    return _execute(cmd, output_file, output_format, process_timeout)


def scan_url(
    input_path: str,
    output_file: str,
    *,
    output_format: str = "json",
    max_url: int = 50,
    only_findings: bool = False,
    ignore: Optional[list[str]] = None,
    processes: int = -1,
    timeout: int = 120,
    quiet: bool = False,
    scancode_dir: Optional[str] = None,
    process_timeout: int = 600,
) -> tuple[str, Optional[dict]]:
    """
    Scan <input_path> for URLs.

    Parameters
    ----------
    max_url : maximum number of URLs to report per file (0 = no limit)
    """
    exe = _get_executable(scancode_dir)
    cmd = [exe, "--url", "--max-url", str(max_url)]
    cmd += _build_output_flags(output_format, output_file)
    if only_findings:
        cmd.append("--only-findings")
    for pat in (ignore or []):
        cmd += ["--ignore", pat]
    cmd += ["-n", str(processes), "--timeout", str(timeout)]
    if quiet:
        cmd.append("--quiet")
    cmd.append(input_path)
    return _execute(cmd, output_file, output_format, process_timeout)


# ──────────────────────────────────────────────────────────────────────────────
# Combined / full scan (recommended entry point for multi-type scans)
# ──────────────────────────────────────────────────────────────────────────────

def scan_full(
    input_path: str,
    output_file: str,
    *,
    # --- primary scan toggles ---
    license: bool = True,
    package: bool = True,
    copyright: bool = True,
    info: bool = False,
    email: bool = False,
    url: bool = False,
    generated: bool = False,
    system_package: bool = False,
    package_in_compiled: bool = False,
    # --- license scan options ---
    license_score: int = 0,
    license_text: bool = False,
    license_text_diagnostics: bool = False,
    license_diagnostics: bool = False,
    unknown_licenses: bool = False,
    # --- email / url limits ---
    max_email: int = 50,
    max_url: int = 50,
    # --- output ---
    output_format: str = "json",
    only_findings: bool = False,
    ignore_author: Optional[str] = None,
    ignore_copyright_holder: Optional[str] = None,
    full_root: bool = False,
    strip_root: bool = False,
    # --- pre-scan ---
    ignore: Optional[list[str]] = None,
    include: Optional[list[str]] = None,
    facet: Optional[dict[str, str]] = None,
    max_depth: int = 0,
    # --- post-scan ---
    classify: bool = False,
    consolidate: bool = False,
    filter_clues: bool = False,
    license_references: bool = False,
    license_clarity_score: bool = False,
    license_policy: Optional[str] = None,
    tallies: bool = False,
    tallies_by_facet: bool = False,
    tallies_key_files: bool = False,
    tallies_with_details: bool = False,
    summary: bool = False,
    todo: bool = False,
    mark_source: bool = False,
    # --- core ---
    processes: int = -1,
    timeout: int = 120,
    max_in_memory: int = 10000,
    quiet: bool = False,
    # --- wrapper ---
    scancode_dir: Optional[str] = None,
    process_timeout: int = 600,
) -> tuple[str, Optional[dict]]:
    """
    Run any combination of scans in a single subprocess call.
    This is the most flexible function — prefer it when you need
    more than one scan type simultaneously.

    Parameters
    ----------
    license               : scan for licenses
    package               : scan for package manifests
    copyright             : scan for copyrights
    info                  : scan for file info (size, checksums)
    email                 : scan for email addresses
    url                   : scan for URLs
    generated             : classify auto-generated files
    system_package        : scan for system package databases
    package_in_compiled   : scan compiled Go/Rust binaries for packages
    facet                 : dict mapping facet names to glob patterns
                            e.g. {"core": "src/*", "tests": "tests/*"}
    consolidate           : group results by package or license + copyright
                            (requires license=True and copyright=True)

    All other parameters are shared with the individual scan functions.

    Returns
    -------
    tuple[str, Optional[dict]]
        (raw_json_string, parsed_dict)
    """
    exe = _get_executable(scancode_dir)
    cmd = [exe]

    # primary scan flags
    if license:
        cmd.append("--license")
    if package:
        cmd.append("--package")
    if copyright:
        cmd.append("--copyright")
    if info:
        cmd.append("--info")
    if email:
        cmd.append("--email")
    if url:
        cmd.append("--url")
    if generated:
        cmd.append("--generated")
    if system_package:
        cmd.append("--system-package")
    if package_in_compiled:
        cmd.append("--package-in-compiled")

    # license-specific options
    if license_score > 0:
        cmd += ["--license-score", str(license_score)]
    if license_text:
        cmd.append("--license-text")
    if license_text_diagnostics:
        cmd.append("--license-text-diagnostics")
    if license_diagnostics:
        cmd.append("--license-diagnostics")
    if unknown_licenses:
        cmd.append("--unknown-licenses")

    # email / url limits
    if email:
        cmd += ["--max-email", str(max_email)]
    if url:
        cmd += ["--max-url", str(max_url)]

    # output format
    cmd += _build_output_flags(output_format, output_file)

    # output filters
    if only_findings:
        cmd.append("--only-findings")
    if ignore_author:
        cmd += ["--ignore-author", ignore_author]
    if ignore_copyright_holder:
        cmd += ["--ignore-copyright-holder", ignore_copyright_holder]

    # output control
    if full_root:
        cmd.append("--full-root")
    if strip_root:
        cmd.append("--strip-root")

    # pre-scan
    for pat in (ignore or []):
        cmd += ["--ignore", pat]
    for pat in (include or []):
        cmd += ["--include", pat]
    for facet_name, pattern in (facet or {}).items():
        cmd += ["--facet", f"{facet_name}={pattern}"]
    if max_depth > 0:
        cmd += ["--max-depth", str(max_depth)]

    # post-scan
    if classify:
        cmd.append("--classify")
    if consolidate:
        cmd.append("--consolidate")
    if filter_clues:
        cmd.append("--filter-clues")
    if license_references:
        cmd.append("--license-references")
    if license_clarity_score:
        cmd.append("--license-clarity-score")
    if license_policy:
        cmd += ["--license-policy", license_policy]
    if tallies:
        cmd.append("--tallies")
    if tallies_by_facet:
        cmd.append("--tallies-by-facet")
    if tallies_key_files:
        cmd.append("--tallies-key-files")
    if tallies_with_details:
        cmd.append("--tallies-with-details")
    if summary:
        cmd.append("--summary")
    if todo:
        cmd.append("--todo")
    if mark_source:
        cmd.append("--mark-source")

    # core
    cmd += ["-n", str(processes), "--timeout", str(timeout)]
    cmd += ["--max-in-memory", str(max_in_memory)]
    if quiet:
        cmd.append("--quiet")

    cmd.append(input_path)
    return _execute(cmd, output_file, output_format, process_timeout)


# ──────────────────────────────────────────────────────────────────────────────
# Reprocess an existing JSON scan result without re-scanning files
# ──────────────────────────────────────────────────────────────────────────────

def reprocess_from_json(
    input_json: str,
    output_file: str,
    *,
    output_format: str = "json-pp",
    classify: bool = False,
    consolidate: bool = False,
    filter_clues: bool = False,
    license_clarity_score: bool = False,
    license_references: bool = False,
    tallies: bool = False,
    tallies_by_facet: bool = False,
    tallies_key_files: bool = False,
    tallies_with_details: bool = False,
    summary: bool = False,
    todo: bool = False,
    mark_source: bool = False,
    quiet: bool = False,
    scancode_dir: Optional[str] = None,
    process_timeout: int = 300,
) -> tuple[str, Optional[dict]]:
    """
    Load a previously generated scancode JSON file and apply post-scan
    plugins to it without re-scanning any files on disk.
    Uses the --from-json flag.

    Useful for applying new post-scan analysis (tallies, classify, etc.)
    to an old result without paying the full scan cost again.

    Parameters
    ----------
    input_json : path to an existing scancode JSON output file

    All other parameters are identical to scan_full() post-scan options.
    """
    exe = _get_executable(scancode_dir)
    cmd = [exe, "--from-json"]
    cmd += _build_output_flags(output_format, output_file)

    if classify:
        cmd.append("--classify")
    if consolidate:
        cmd.append("--consolidate")
    if filter_clues:
        cmd.append("--filter-clues")
    if license_clarity_score:
        cmd.append("--license-clarity-score")
    if license_references:
        cmd.append("--license-references")
    if tallies:
        cmd.append("--tallies")
    if tallies_by_facet:
        cmd.append("--tallies-by-facet")
    if tallies_key_files:
        cmd.append("--tallies-key-files")
    if tallies_with_details:
        cmd.append("--tallies-with-details")
    if summary:
        cmd.append("--summary")
    if todo:
        cmd.append("--todo")
    if mark_source:
        cmd.append("--mark-source")
    if quiet:
        cmd.append("--quiet")

    cmd.append(input_json)
    return _execute(cmd, output_file, output_format, process_timeout)


# ──────────────────────────────────────────────────────────────────────────────
# Introspection helpers (return plain strings, no output file needed)
# ──────────────────────────────────────────────────────────────────────────────

def get_version(scancode_dir: Optional[str] = None) -> str:
    """Return the installed scancode version string."""
    exe = _get_executable(scancode_dir)
    result = subprocess.run([exe, "--version"], capture_output=True, text=True)
    return result.stdout.strip()


def list_plugins(scancode_dir: Optional[str] = None) -> str:
    """Return the list of available scancode plugins as a string."""
    exe = _get_executable(scancode_dir)
    result = subprocess.run([exe, "--plugins"], capture_output=True, text=True)
    return result.stdout


def list_packages(scancode_dir: Optional[str] = None) -> str:
    """Return the list of supported package manifest parsers as a string."""
    exe = _get_executable(scancode_dir)
    result = subprocess.run([exe, "--list-packages"], capture_output=True, text=True)
    return result.stdout


def get_examples(scancode_dir: Optional[str] = None) -> str:
    """Return the built-in scancode usage examples as a string."""
    exe = _get_executable(scancode_dir)
    result = subprocess.run([exe, "--examples"], capture_output=True, text=True)
    return result.stdout


def print_options(
    *flags: str,
    scancode_dir: Optional[str] = None,
) -> str:
    """
    Return the selected options string for a hypothetical command.
    Uses --print-options to preview what scancode would actually run.

    Parameters
    ----------
    *flags : scancode flag strings to include, e.g. "--license", "--json", "out.json"
    """
    exe = _get_executable(scancode_dir)
    result = subprocess.run(
        [exe, *flags, "--print-options"],
        capture_output=True,
        text=True,
    )
    return result.stdout


# ──────────────────────────────────────────────────────────────────────────────
# Parsed result helper functions
# ──────────────────────────────────────────────────────────────────────────────

def extract_licenses(parsed: dict) -> list[dict]:
    """
    Return all top-level license detections from a parsed scan result.

    Each item in the returned list contains:
      - identifier              : unique detection ID
      - license_expression      : e.g. "mit AND apache-2.0"
      - license_expression_spdx : e.g. "MIT AND Apache-2.0"
      - detection_count         : number of times this detection appears
      - reference_matches       : list of individual rule matches
    """
    return parsed.get("license_detections", [])


def extract_files_with_licenses(parsed: dict) -> list[dict]:
    """
    Return only the file entries that have at least one license detection.
    Filters out directories and files with no detected license expression.
    """
    return [
        f for f in parsed.get("files", [])
        if f.get("detected_license_expression")
    ]


def extract_packages(parsed: dict) -> list[dict]:
    """
    Return all package detections from a parsed scan result.
    Each item represents one package manifest or dependency found.
    """
    return parsed.get("packages", [])


def extract_dependencies(parsed: dict) -> list[dict]:
    """
    Return all dependency entries from a parsed scan result.
    Dependencies are distinct from packages — they are the declared
    requirements found inside manifest files.
    """
    return parsed.get("dependencies", [])


def extract_copyrights(parsed: dict) -> list[dict]:
    """
    Return all copyright statements across all files, flattened into a
    single list with the source file path included in each item.

    Each returned dict contains:
      - file       : relative path of the source file
      - copyright  : the copyright statement string
      - start_line : line number where the statement starts
      - end_line   : line number where the statement ends
    """
    results = []
    for f in parsed.get("files", []):
        for c in f.get("copyrights", []):
            results.append({"file": f["path"], **c})
    return results


def extract_emails(parsed: dict) -> list[dict]:
    """
    Return all email addresses found across all scanned files.
    Each item includes the source file path.
    """
    results = []
    for f in parsed.get("files", []):
        for e in f.get("emails", []):
            results.append({"file": f["path"], **e})
    return results


def extract_urls(parsed: dict) -> list[dict]:
    """
    Return all URLs found across all scanned files.
    Each item includes the source file path.
    """
    results = []
    for f in parsed.get("files", []):
        for u in f.get("urls", []):
            results.append({"file": f["path"], **u})
    return results


def extract_scan_errors(parsed: dict) -> list[dict]:
    """
    Return all files that had scan errors, with their error messages.

    Each returned dict contains:
      - path   : relative file path
      - errors : list of error strings reported by scancode
    """
    return [
        {"path": f["path"], "errors": f["scan_errors"]}
        for f in parsed.get("files", [])
        if f.get("scan_errors")
    ]


def get_summary_stats(parsed: dict) -> dict:
    """
    Return a high-level summary dict extracted from the scan headers.

    Returned keys
    -------------
    tool_version      : scancode version string
    duration_seconds  : total scan duration
    files_count       : number of files scanned
    total_resources   : total files + directories in output
    files_with_license: number of files with at least one license detection
    errors            : list of scan-level errors
    warnings          : list of scan-level warnings
    spdx_list_version : SPDX license list version used
    """
    headers = parsed.get("headers", [{}])[0]
    files = parsed.get("files", [])
    extra = headers.get("extra_data", {})
    return {
        "tool_version": headers.get("tool_version"),
        "duration_seconds": round(headers.get("duration", 0), 2),
        "files_count": extra.get("files_count", 0),
        "total_resources": len(files),
        "files_with_license": sum(
            1 for f in files if f.get("detected_license_expression")
        ),
        "errors": headers.get("errors", []),
        "warnings": headers.get("warnings", []),
        "spdx_list_version": extra.get("spdx_license_list_version"),
    }


def filter_by_license(parsed: dict, spdx_id: str) -> list[dict]:
    """
    Return only file entries whose detected SPDX license expression
    contains the given SPDX identifier (case-insensitive substring match).

    Example
    -------
    >>> mit_files = filter_by_license(parsed, "MIT")
    >>> gpl_files = filter_by_license(parsed, "GPL-2.0")
    """
    spdx_id_lower = spdx_id.lower()
    return [
        f for f in parsed.get("files", [])
        if spdx_id_lower in (f.get("detected_license_expression_spdx") or "").lower()
    ]


def get_unique_licenses(parsed: dict) -> list[str]:
    """
    Return a deduplicated sorted list of all SPDX license identifiers
    found across the entire scanned codebase.
    """
    seen: set[str] = set()
    for detection in parsed.get("license_detections", []):
        expr = detection.get("license_expression_spdx", "")
        for token in expr.replace("(", "").replace(")", "").split():
            if token not in {"AND", "OR", "WITH"}:
                seen.add(token)
    return sorted(seen)
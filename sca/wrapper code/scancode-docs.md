# ScanCode-Toolkit — Developer Reference

Complete CLI documentation and Python subprocess guide for **scancode-toolkit v32.x**.  
Use this alongside `scancode_wrapper.py` to call scancode programmatically.

---

## Table of Contents

1. [Overview](#overview)
2. [Setup](#setup)
3. [Executable Detection (Cross-Platform)](#executable-detection)
4. [Output Formats](#output-formats)
5. [Primary Scan Functions](#primary-scan-functions)
   - [scan_license](#scan_license)
   - [scan_package](#scan_package)
   - [scan_copyright](#scan_copyright)
   - [scan_system_package](#scan_system_package)
   - [scan_package_in_compiled](#scan_package_in_compiled)
   - [scan_package_only](#scan_package_only)
   - [scan_info](#scan_info)
   - [scan_email](#scan_email)
   - [scan_url](#scan_url)
   - [scan_full](#scan_full)
6. [Reprocessing Existing Results](#reprocessing-existing-results)
7. [Scan Options Reference](#scan-options-reference)
8. [Output Filters Reference](#output-filters-reference)
9. [Output Control Reference](#output-control-reference)
10. [Pre-Scan Options Reference](#pre-scan-options-reference)
11. [Post-Scan Options Reference](#post-scan-options-reference)
12. [Core Options Reference](#core-options-reference)
13. [Introspection Functions](#introspection-functions)
14. [Parsed Result Helpers](#parsed-result-helpers)
15. [Recipes](#recipes)
16. [Error Handling](#error-handling)
17. [Performance Notes](#performance-notes)

---

## Overview

ScanCode-Toolkit is a CLI tool that detects licenses, copyrights, packages,
emails, and URLs inside source code repositories or individual files.
It writes results to a file in your chosen format (JSON, SPDX, CycloneDX, etc.).

The `scancode_wrapper.py` module wraps every CLI flag as a typed Python function
parameter. Each public function returns a `(raw, parsed)` tuple:

- `raw`    — the JSON string read from the output file
- `parsed` — the decoded Python `dict`, or `None` for non-JSON formats

---

## Setup

```python
from scancode_wrapper import scan_license, scan_full, get_summary_stats
```

**Locating the scancode executable:**

If scancode is on your `PATH`:
```python
raw, parsed = scan_license("./my_repo", "out.json")
```

If scancode is in a specific directory (e.g. a project-local install):
```python
raw, parsed = scan_license(
    "./my_repo",
    "out.json",
    scancode_dir="D:/HACKATHON PROJECT/repo-llm/scancode-toolkit",
)
```

---

## Executable Detection

```python
from scancode_wrapper import _get_executable

exe = _get_executable()
# Windows → "scancode.bat"
# Linux / macOS → "scancode"

exe = _get_executable("/opt/scancode-toolkit")
# Windows → "/opt/scancode-toolkit/scancode.bat"
# Linux   → "/opt/scancode-toolkit/scancode"
```

The platform check uses `platform.system() == "Windows"`.

---

## Output Formats

Pass the format name as `output_format` to any scan function.
The output file is always written to `output_file`.

| `output_format` | CLI flag            | Notes                                          |
|-----------------|---------------------|------------------------------------------------|
| `json`          | `--json`            | Compact JSON. Default. Parseable by wrapper.   |
| `json-pp`       | `--json-pp`         | Pretty-printed JSON. Human-readable.           |
| `json-lines`    | `--json-lines`      | NDJSON. One JSON object per line.              |
| `yaml`          | `--yaml`            | YAML output.                                   |
| `csv`           | `--csv`             | CSV. Deprecated upstream; use with care.       |
| `html`          | `--html`            | HTML report.                                   |
| `cyclonedx`     | `--cyclonedx`       | CycloneDX JSON (SBOM standard).                |
| `cyclonedx-xml` | `--cyclonedx-xml`   | CycloneDX XML (SBOM standard).                 |
| `spdx-rdf`      | `--spdx-rdf`        | SPDX RDF format.                               |
| `spdx-tv`       | `--spdx-tv`         | SPDX Tag-Value format.                         |
| `debian`        | `--debian`          | Machine-readable Debian copyright format.      |

> **Note:** `parsed` is `None` for all non-JSON formats. For `json-lines`,
> `parsed` is `{"lines": [list of dicts]}`.

**CLI equivalent:**
```bash
scancode --license --json-pp out.json ./my_repo
scancode --license --spdx-tv out.spdx ./my_repo
scancode --license --copyright --cyclonedx sbom.json ./my_repo
```

---

## Primary Scan Functions

---

### scan_license

Scan a file or directory for software licenses.

```python
raw, parsed = scan_license(
    input_path  = "./my_repo",
    output_file = "licenses.json",

    # scan options
    output_format           = "json",     # see Output Formats table
    license_score           = 0,          # 0-100; discard matches below this
    license_text            = False,      # include matched text in results
    license_text_diagnostics= False,      # highlight unmatched words
    license_diagnostics     = False,      # include post-processing details
    unknown_licenses        = False,      # (experimental) detect unknown licenses

    # output filters
    only_findings           = False,      # omit files with no detections
    ignore_author           = None,       # regex: skip files matching author
    ignore_copyright_holder = None,       # regex: skip files matching holder

    # output control
    full_root               = False,      # report absolute paths
    strip_root              = False,      # strip root dir from all paths

    # pre-scan
    ignore                  = None,       # list of glob patterns to skip
    include                 = None,       # list of glob patterns to restrict to
    max_depth               = 0,          # 0 = unlimited depth

    # post-scan
    classify                = False,      # classify as legal/readme/test/etc.
    filter_clues            = False,      # remove clues already in detections
    license_references      = False,      # include full rule reference data
    license_clarity_score   = False,      # compute codebase clarity score
    license_policy          = None,       # path to license policy YAML file
    tallies                 = False,      # per-license tallies at codebase level
    tallies_by_facet        = False,
    tallies_key_files       = False,
    tallies_with_details    = False,
    summary                 = False,      # declared origin summary
    todo                    = False,      # list ambiguous detections
    mark_source             = False,      # flag dirs with >90% source files

    # core
    processes               = -1,         # -1=no threading, 0=no parallel, N=N workers
    timeout                 = 120,        # per-file timeout in seconds
    max_in_memory           = 10000,      # 0=unlimited RAM, -1=disk only
    quiet                   = False,      # suppress progress bar

    # wrapper
    scancode_dir            = None,       # path to scancode install dir
    process_timeout         = 600,        # Python subprocess timeout in seconds
)
```

**Equivalent CLI commands:**

Minimal:
```bash
scancode --license --json licenses.json ./my_repo
```

With confidence filter and pretty output:
```bash
scancode --license --license-score 70 --json-pp licenses.json ./my_repo
```

Full-featured:
```bash
scancode --license \
  --license-score 70 \
  --license-text \
  --classify \
  --filter-clues \
  --license-clarity-score \
  --tallies \
  --only-findings \
  --ignore "*.min.js" \
  -n 4 \
  --timeout 120 \
  --json-pp licenses.json \
  ./my_repo
```

---

### scan_package

Scan for application package manifests and dependency lockfiles
(e.g. `package.json`, `requirements.txt`, `setup.py`, `Cargo.toml`).

```python
raw, parsed = scan_package(
    input_path  = "./my_repo",
    output_file = "packages.json",

    output_format = "json",
    only_findings = False,
    full_root     = False,
    strip_root    = False,
    ignore        = None,
    include       = None,
    max_depth     = 0,

    classify      = False,
    consolidate   = False,   # group by package/license+copyright (needs all three scans)
    tallies       = False,
    summary       = False,

    processes     = -1,
    timeout       = 120,
    max_in_memory = 10000,
    quiet         = False,

    scancode_dir    = None,
    process_timeout = 600,
)
```

**Equivalent CLI:**
```bash
scancode --package --json packages.json ./my_repo
```

---

### scan_copyright

Scan for copyright statements in source files.

```python
raw, parsed = scan_copyright(
    input_path  = "./my_repo",
    output_file = "copyrights.json",

    output_format           = "json",
    only_findings           = False,
    ignore_author           = None,       # regex: skip files by author match
    ignore_copyright_holder = None,       # regex: skip files by holder match
    full_root               = False,
    strip_root              = False,
    ignore                  = None,
    include                 = None,
    max_depth               = 0,

    classify  = False,
    tallies   = False,
    summary   = False,

    processes     = -1,
    timeout       = 120,
    max_in_memory = 10000,
    quiet         = False,

    scancode_dir    = None,
    process_timeout = 600,
)
```

**Equivalent CLI:**
```bash
scancode --copyright --json copyrights.json ./my_repo

# Ignore files whose copyright holder matches a pattern:
scancode --copyright \
  --ignore-copyright-holder "Google LLC" \
  --json copyrights.json ./my_repo
```

---

### scan_system_package

Scan for installed system package databases such as dpkg status files
or RPM package databases. Typically run on container filesystems or
OS images rather than source repositories.

```python
raw, parsed = scan_system_package(
    input_path  = "/var/lib/dpkg",
    output_file = "sys_packages.json",

    output_format = "json",
    only_findings = False,
    processes     = -1,
    timeout       = 120,
    quiet         = False,

    scancode_dir    = None,
    process_timeout = 600,
)
```

**Equivalent CLI:**
```bash
scancode --system-package --json sys_packages.json /var/lib/dpkg
```

---

### scan_package_in_compiled

Scan compiled binaries for embedded package and dependency metadata.
Currently supported binary types: **Go** binaries, **Rust** binaries.

```python
raw, parsed = scan_package_in_compiled(
    input_path  = "./dist/my_go_binary",
    output_file = "compiled_packages.json",

    output_format   = "json",
    processes       = -1,
    timeout         = 120,
    quiet           = False,
    scancode_dir    = None,
    process_timeout = 600,
)
```

**Equivalent CLI:**
```bash
scancode --package-in-compiled --json compiled_packages.json ./dist/my_go_binary
```

---

### scan_package_only

Scan for package data only, explicitly skipping license and copyright detection.
Faster than `scan_package()` when you only need dependency manifests.

```python
raw, parsed = scan_package_only(
    input_path  = "./my_repo",
    output_file = "deps_only.json",

    output_format   = "json",
    processes       = -1,
    timeout         = 120,
    quiet           = False,
    scancode_dir    = None,
    process_timeout = 600,
)
```

**Equivalent CLI:**
```bash
scancode --package-only --json deps_only.json ./my_repo
```

---

### scan_info

Scan for file-level metadata: size in bytes, MD5/SHA1/SHA256 checksums,
MIME type, detected programming language, and binary/text classification.

```python
raw, parsed = scan_info(
    input_path  = "./my_repo",
    output_file = "file_info.json",

    output_format = "json",
    generated     = False,    # also classify auto-generated files
    full_root     = False,
    strip_root    = False,
    ignore        = None,
    max_depth     = 0,
    mark_source   = False,

    processes       = -1,
    timeout         = 120,
    quiet           = False,
    scancode_dir    = None,
    process_timeout = 600,
)
```

**Equivalent CLI:**
```bash
scancode --info --json file_info.json ./my_repo

# Also flag auto-generated files:
scancode --info --generated --json file_info.json ./my_repo
```

---

### scan_email

Scan for email addresses embedded in source files.

```python
raw, parsed = scan_email(
    input_path  = "./my_repo",
    output_file = "emails.json",

    output_format = "json",
    max_email     = 50,       # max emails per file; 0 = no limit
    only_findings = False,
    ignore        = None,

    processes       = -1,
    timeout         = 120,
    quiet           = False,
    scancode_dir    = None,
    process_timeout = 600,
)
```

**Equivalent CLI:**
```bash
scancode --email --max-email 0 --json emails.json ./my_repo
```

---

### scan_url

Scan for URLs embedded in source files.

```python
raw, parsed = scan_url(
    input_path  = "./my_repo",
    output_file = "urls.json",

    output_format = "json",
    max_url       = 50,       # max URLs per file; 0 = no limit
    only_findings = False,
    ignore        = None,

    processes       = -1,
    timeout         = 120,
    quiet           = False,
    scancode_dir    = None,
    process_timeout = 600,
)
```

**Equivalent CLI:**
```bash
scancode --url --max-url 0 --json urls.json ./my_repo
```

---

### scan_full

Run any combination of scan types in a single subprocess call.
**This is the recommended function when you need more than one scan type.**

```python
raw, parsed = scan_full(
    input_path  = "./my_repo",
    output_file = "full_scan.json",

    # --- primary scan toggles ---
    license             = True,
    package             = True,
    copyright           = True,
    info                = False,
    email               = False,
    url                 = False,
    generated           = False,
    system_package      = False,
    package_in_compiled = False,

    # --- license options ---
    license_score            = 0,
    license_text             = False,
    license_text_diagnostics = False,
    license_diagnostics      = False,
    unknown_licenses         = False,

    # --- email / url limits ---
    max_email = 50,
    max_url   = 50,

    # --- output ---
    output_format           = "json",
    only_findings           = False,
    ignore_author           = None,
    ignore_copyright_holder = None,
    full_root               = False,
    strip_root              = False,

    # --- pre-scan ---
    ignore    = None,         # e.g. ["*.min.js", "node_modules/*"]
    include   = None,         # e.g. ["src/*"]
    facet     = None,         # e.g. {"core": "src/*", "tests": "tests/*"}
    max_depth = 0,

    # --- post-scan ---
    classify              = False,
    consolidate           = False,
    filter_clues          = False,
    license_references    = False,
    license_clarity_score = False,
    license_policy        = None,     # path to policy YAML file
    tallies               = False,
    tallies_by_facet      = False,
    tallies_key_files     = False,
    tallies_with_details  = False,
    summary               = False,
    todo                  = False,
    mark_source           = False,

    # --- core ---
    processes     = -1,
    timeout       = 120,
    max_in_memory = 10000,
    quiet         = False,

    # --- wrapper ---
    scancode_dir    = None,
    process_timeout = 600,
)
```

**Equivalent CLI:**
```bash
# License + copyright + package in one call:
scancode --license --copyright --package --json full_scan.json ./my_repo

# Compliance-grade scan with all post-scan analysis:
scancode --license --copyright --package \
  --license-score 70 \
  --classify \
  --consolidate \
  --filter-clues \
  --license-clarity-score \
  --license-references \
  --tallies \
  --summary \
  --only-findings \
  --ignore "*.min.js" \
  --ignore "node_modules/*" \
  --ignore "*.lock" \
  -n 8 \
  --timeout 120 \
  --json-pp full_scan.json \
  ./my_repo

# Output as CycloneDX SBOM:
scancode --license --package --copyright \
  --cyclonedx sbom.json ./my_repo
```

---

## Reprocessing Existing Results

Apply post-scan plugins to an existing JSON result without re-scanning files.

```python
from scancode_wrapper import reprocess_from_json

raw, parsed = reprocess_from_json(
    input_json  = "previous_scan.json",
    output_file = "enhanced_scan.json",

    output_format         = "json-pp",
    classify              = True,
    consolidate           = False,
    filter_clues          = True,
    license_clarity_score = True,
    license_references    = False,
    tallies               = True,
    tallies_by_facet      = False,
    tallies_key_files     = False,
    tallies_with_details  = False,
    summary               = True,
    todo                  = False,
    mark_source           = False,
    quiet                 = False,

    scancode_dir    = None,
    process_timeout = 300,
)
```

**Equivalent CLI:**
```bash
scancode --from-json previous_scan.json \
  --classify \
  --filter-clues \
  --license-clarity-score \
  --tallies \
  --summary \
  --json-pp enhanced_scan.json
```

> **When to use this:** You have a raw JSON scan from a CI run and want to add
> tallies or a clarity score without waiting for another full scan.

---

## Scan Options Reference

These options modify how the license detection engine behaves.
All apply to `scan_license()` and `scan_full()`.

| Parameter / Flag                     | Type  | Default | Description |
|--------------------------------------|-------|---------|-------------|
| `license_score` / `--license-score`  | int   | 0       | Discard matches with confidence below this value (0–100). 70 is a reasonable threshold for production use. |
| `license_text` / `--license-text`    | bool  | False   | Include the exact matched text for each detection in the output. |
| `license_text_diagnostics` / `--license-text-diagnostics` | bool | False | In the matched text, highlight with `[]` any words that were not matched. |
| `license_diagnostics` / `--license-diagnostics` | bool | False | Include diagnostic details about post-processing steps applied to each detection. |
| `unknown_licenses` / `--unknown-licenses` | bool | False | **Experimental.** Attempt to detect licenses that don't match any known rule. |
| `max_email` / `--max-email`          | int   | 50      | Max email addresses to report per file. Set to 0 for no limit. |
| `max_url` / `--max-url`              | int   | 50      | Max URLs to report per file. Set to 0 for no limit. |

---

## Output Filters Reference

These filters reduce the volume of output by dropping unwanted results.

| Parameter / Flag                               | Type   | Description |
|------------------------------------------------|--------|-------------|
| `only_findings` / `--only-findings`            | bool   | Only include files/directories that have at least one finding. Files with no results are omitted. |
| `ignore_author` / `--ignore-author`            | str    | Regex pattern. Ignore a file entirely if any detected author matches. |
| `ignore_copyright_holder` / `--ignore-copyright-holder` | str | Regex pattern. Ignore a file entirely if any copyright holder matches. |

**CLI examples:**
```bash
# Only show files that actually have findings:
scancode --license --only-findings --json out.json ./repo

# Skip files where the copyright holder is "Google":
scancode --copyright --ignore-copyright-holder "Google" --json out.json ./repo
```

---

## Output Control Reference

These flags control how paths are reported in the output.

| Parameter / Flag           | Description |
|----------------------------|-------------|
| `full_root` / `--full-root`   | Report the full absolute path for every file (e.g. `/home/user/repo/src/main.py`). |
| `strip_root` / `--strip-root` | Strip the scanned root directory from all paths (e.g. `src/main.py` instead of `repo/src/main.py`). |

> Only one of `full_root` or `strip_root` should be set at a time.

---

## Pre-Scan Options Reference

These options control which files are included before scanning begins.

| Parameter / Flag              | Type              | Description |
|-------------------------------|-------------------|-------------|
| `ignore` / `--ignore`         | `list[str]`       | List of glob patterns. Files matching any pattern are excluded entirely. Applied before scanning. |
| `include` / `--include`       | `list[str]`       | List of glob patterns. Only files matching at least one pattern are scanned. |
| `facet` / `--facet`           | `dict[str, str]`  | Assign facet labels to files by path pattern. Keys are facet names (`core`, `tests`, `docs`, etc.), values are glob patterns. |
| `max_depth` / `--max-depth`   | int               | Maximum directory depth to descend. 0 means unlimited. |

**CLI examples:**
```bash
# Exclude minified JS and lock files:
scancode --license \
  --ignore "*.min.js" \
  --ignore "*.lock" \
  --ignore "node_modules/*" \
  --json out.json ./repo

# Only scan Python files:
scancode --license --include "*.py" --json out.json ./repo

# Scan only top 2 levels:
scancode --license --max-depth 2 --json out.json ./repo

# Assign facets:
scancode --license \
  --facet "core=src/*" \
  --facet "tests=tests/*" \
  --facet "docs=docs/*" \
  --json out.json ./repo
```

---

## Post-Scan Options Reference

These options run additional analysis passes on the completed scan results.

| Parameter / Flag                           | Description |
|--------------------------------------------|-------------|
| `classify` / `--classify`                  | Classify each file with flags: `is_legal`, `is_readme`, `is_manifest`, `is_test`, `is_top_level`. |
| `consolidate` / `--consolidate`            | Group files into consolidated packages and components by license + copyright holder. Requires `--license`, `--copyright`, and `--package` to be active. |
| `filter_clues` / `--filter-clues`          | Remove redundant license clues that are already fully covered by a detected license text or notice. |
| `license_clarity_score` / `--license-clarity-score` | Compute a 0–100 clarity score for the whole codebase indicating how well-declared the licensing is. |
| `license_policy` / `--license-policy`      | Path to a YAML policy file. Applies allowed/restricted/prohibited flags to each detected license. |
| `license_references` / `--license-references` | Include full reference data (text, URLs, aliases) for every license and rule that appears in detections. |
| `mark_source` / `--mark-source`            | Set `is_source: true` on directories where over 90% of children are source code files. |
| `summary` / `--summary`                    | Add declared origin info (primary license, primary copyright holder) at the codebase attribute level. |
| `tallies` / `--tallies`                    | Compute count tallies for licenses, copyrights, and other findings at the codebase level. |
| `tallies_by_facet` / `--tallies-by-facet`  | Same as `tallies` but group results by facet (requires `--facet` assignments). |
| `tallies_key_files` / `--tallies-key-files`| Compute tallies only for key top-level files (requires `--classify`). |
| `tallies_with_details` / `--tallies-with-details` | Include intermediate file-level detail in the tallies output. |
| `todo` / `--todo`                          | Summarise all ambiguous detections that require manual review. |

**CLI example — full compliance scan:**
```bash
scancode --license --copyright --package \
  --classify \
  --consolidate \
  --filter-clues \
  --license-clarity-score \
  --tallies \
  --summary \
  --todo \
  --json-pp compliance_scan.json \
  ./my_repo
```

---

## Core Options Reference

These options control the scanning engine itself.

| Parameter / Flag                        | Default  | Description |
|-----------------------------------------|----------|-------------|
| `processes` / `-n` / `--processes`      | CPUs - 1 | Number of parallel worker processes. `0` = no parallelism. `-1` = disable threading entirely. For debugging, use `-1`. For maximum speed, use CPU count. |
| `timeout` / `--timeout`                 | 120 s    | Stop scanning an individual file after this many seconds. Increase for large or complex files. |
| `max_in_memory` / `--max-in-memory`     | 10000    | Max number of file scan details kept in RAM. `0` = unlimited (fast but memory-hungry). `-1` = use on-disk cache only (slow but low RAM). |
| `quiet` / `-q` / `--quiet`             | False    | Suppress the progress bar and summary output. Useful in CI pipelines. |

**CLI examples:**
```bash
# Use 8 workers, 60s per-file timeout:
scancode --license -n 8 --timeout 60 --json out.json ./repo

# Disable all parallelism (for debugging):
scancode --license -n -1 --json out.json ./repo

# Suppress all output (CI-friendly):
scancode --license --quiet --json out.json ./repo
```

---

## Introspection Functions

These functions query the scancode tool itself without scanning any files.

```python
from scancode_wrapper import (
    get_version,
    list_plugins,
    list_packages,
    get_examples,
    print_options,
)

# Check installed version:
print(get_version())
# → "ScanCode version 32.5.0"

# List all available plugins:
print(list_plugins())

# List supported package manifest parsers:
print(list_packages())

# Show built-in usage examples:
print(get_examples())

# Preview which options scancode would use for a given flag set:
print(print_options("--license", "--json", "out.json", "--classify"))
```

All functions accept `scancode_dir=None` as an optional keyword argument
if scancode is not on PATH.

---

## Parsed Result Helpers

Import any of these to extract specific data from a `parsed` dict
returned by any scan function.

```python
from scancode_wrapper import (
    extract_licenses,
    extract_files_with_licenses,
    extract_packages,
    extract_dependencies,
    extract_copyrights,
    extract_emails,
    extract_urls,
    extract_scan_errors,
    get_summary_stats,
    filter_by_license,
    get_unique_licenses,
)
```

### `get_summary_stats(parsed)`

High-level scan summary extracted from the headers.

```python
stats = get_summary_stats(parsed)
# {
#   "tool_version": "v32.5.0",
#   "duration_seconds": 62.56,
#   "files_count": 168,
#   "total_resources": 195,
#   "files_with_license": 12,
#   "errors": [],
#   "warnings": [],
#   "spdx_list_version": "3.28"
# }
```

### `extract_licenses(parsed)`

All top-level license detections. Each item has:
- `license_expression` — e.g. `"mit AND apache-2.0"`
- `license_expression_spdx` — e.g. `"MIT AND Apache-2.0"`
- `detection_count` — how many files contain this detection
- `reference_matches` — list of individual rule matches with scores

```python
for detection in extract_licenses(parsed):
    print(detection["license_expression_spdx"])
```

### `extract_files_with_licenses(parsed)`

Only file entries that have at least one detected license.

```python
licensed_files = extract_files_with_licenses(parsed)
for f in licensed_files:
    print(f["path"], "→", f["detected_license_expression_spdx"])
```

### `extract_packages(parsed)`

All detected package manifests and their metadata.

```python
for pkg in extract_packages(parsed):
    print(pkg.get("name"), pkg.get("version"), pkg.get("license_expression"))
```

### `extract_dependencies(parsed)`

All declared dependencies found in manifest files.

```python
for dep in extract_dependencies(parsed):
    print(dep.get("purl"))  # Package URL
```

### `extract_copyrights(parsed)`

All copyright statements, flattened across all files.

```python
for c in extract_copyrights(parsed):
    print(c["file"], "→", c.get("copyright"))
```

### `extract_emails(parsed)` / `extract_urls(parsed)`

```python
for item in extract_emails(parsed):
    print(item["file"], "→", item.get("email"))

for item in extract_urls(parsed):
    print(item["file"], "→", item.get("url"))
```

### `extract_scan_errors(parsed)`

Files that caused errors during scanning.

```python
errors = extract_scan_errors(parsed)
if errors:
    for e in errors:
        print("ERROR in", e["path"], ":", e["errors"])
```

### `filter_by_license(parsed, spdx_id)`

Return only files whose SPDX expression contains a given identifier.

```python
gpl_files = filter_by_license(parsed, "GPL-2.0")
mit_files  = filter_by_license(parsed, "MIT")
```

### `get_unique_licenses(parsed)`

Sorted list of all distinct SPDX license IDs found in the codebase.

```python
licenses = get_unique_licenses(parsed)
# → ["Apache-2.0", "MIT", "OFL-1.1"]
```

---

## Recipes

### Recipe 1 — Minimal license scan

```python
from scancode_wrapper import scan_license, get_unique_licenses

raw, parsed = scan_license("./my_repo", "out.json", quiet=True)
print("Licenses found:", get_unique_licenses(parsed))
```

### Recipe 2 — High-confidence compliance scan with SPDX output

```python
from scancode_wrapper import scan_full

raw, parsed = scan_full(
    input_path  = "./my_repo",
    output_file = "sbom.spdx",
    output_format = "spdx-tv",
    license      = True,
    package      = True,
    copyright    = True,
    license_score = 70,
    filter_clues  = True,
    classify      = True,
    only_findings = True,
    ignore        = ["node_modules/*", "*.min.js", "*.lock"],
    processes     = 4,
    quiet         = True,
)
# parsed is None for spdx-tv — read the file directly
with open("sbom.spdx") as f:
    print(f.read())
```

### Recipe 3 — Generate a CycloneDX SBOM

```python
from scancode_wrapper import scan_full

scan_full(
    input_path    = "./my_repo",
    output_file   = "sbom.cdx.json",
    output_format = "cyclonedx",
    license       = True,
    package       = True,
    copyright     = True,
    quiet         = True,
)
```

### Recipe 4 — Find all GPL-licensed files

```python
from scancode_wrapper import scan_license, filter_by_license

_, parsed = scan_license("./my_repo", "out.json", quiet=True)
gpl_files = filter_by_license(parsed, "GPL")
for f in gpl_files:
    print(f["path"], "→", f["detected_license_expression_spdx"])
```

### Recipe 5 — Reprocess without re-scanning

```python
from scancode_wrapper import reprocess_from_json, get_summary_stats

# Original scan was run yesterday; now add tallies without re-scanning:
_, parsed = reprocess_from_json(
    input_json  = "yesterday_scan.json",
    output_file = "enhanced.json",
    tallies               = True,
    license_clarity_score = True,
    classify              = True,
    filter_clues          = True,
)
print(get_summary_stats(parsed))
```

### Recipe 6 — Scan only Python source files, exclude tests

```python
from scancode_wrapper import scan_full

scan_full(
    input_path    = "./my_repo",
    output_file   = "python_only.json",
    license       = True,
    copyright     = True,
    package       = False,
    include       = ["*.py"],
    ignore        = ["tests/*", "test_*.py", "*_test.py"],
    only_findings = True,
    processes     = 4,
    quiet         = True,
)
```

### Recipe 7 — Apply a license policy file

```python
from scancode_wrapper import scan_full

# policy.yml example content:
# - license_key: gpl-2.0
#   label: "Prohibited"
#   color_code: "#C00"
# - license_key: mit
#   label: "Allowed"
#   color_code: "#0C0"

scan_full(
    input_path     = "./my_repo",
    output_file    = "policy_scan.json",
    license        = True,
    copyright      = True,
    license_policy = "policy.yml",
    classify       = True,
    tallies        = True,
    quiet          = True,
)
```

### Recipe 8 — Scan a compiled Go binary

```python
from scancode_wrapper import scan_package_in_compiled

raw, parsed = scan_package_in_compiled(
    input_path  = "./dist/myapp",
    output_file = "go_packages.json",
    processes   = 2,
    quiet       = True,
)
```

---

## Error Handling

```python
from scancode_wrapper import scan_license, extract_scan_errors

try:
    raw, parsed = scan_license(
        input_path  = "./my_repo",
        output_file = "out.json",
        process_timeout = 600,
    )
except RuntimeError as e:
    # scancode exited with a non-zero return code
    print("Scan failed:", e)
except FileNotFoundError as e:
    # Output file was not created — usually means scancode itself crashed
    print("Output file missing:", e)
except TimeoutError:
    # The Python subprocess.run() call timed out
    # Increase process_timeout or reduce the number of files being scanned
    print("Subprocess timed out. Increase process_timeout.")

# Always check for per-file scan errors even on success:
if parsed:
    errors = extract_scan_errors(parsed)
    for e in errors:
        print(f"File error: {e['path']} → {e['errors']}")
```

> **Note:** The `--timeout` parameter (default 120s) is scancode's internal
> per-file timeout. `process_timeout` is the Python `subprocess.run()` ceiling
> for the entire scan process. Always set `process_timeout` to at least
> `(files_count * timeout) / processes` to avoid premature kills.

---

## Performance Notes

| Scenario | Recommendation |
|----------|----------------|
| First ever run on a machine | Expect 60–100s cold-start setup cost. Subsequent warm runs cost ~1–2s setup. |
| Small repos (< 20 files) | Use `-n 0` or `-n -1` — parallelism overhead exceeds benefit at small scale. |
| Large repos (> 100 files) | Use `-n` equal to your physical CPU count for best throughput. |
| Files timing out | Increase `--timeout` above 120s for large generated files or minified JS. |
| Low memory environments | Set `max_in_memory=-1` to use on-disk caching. Slower but memory-safe. |
| CI/CD pipelines | Always pass `--quiet` to suppress the progress bar in non-TTY environments. |
| Reproducibility | Run each scan twice and compare `license_detections`. A mismatch may indicate a worker race condition — treat the run with more detections as authoritative. |
| Confidence | Set `license_score=70` as a baseline for production compliance scans. Detections below 70% are clues, not findings. |
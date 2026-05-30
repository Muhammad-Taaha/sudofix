# DeepVulnerableEngine

A multi‑threaded data processing engine that is intentionally vulnerable.
It contains **6 deep, subtle security defects** and **1 information leak**,
selectable via the `USE_VULNERABLE` CMake option (default: OFF).

## Requirements

- C++17 compiler (GCC ≥ 8, Clang ≥ 7)
- CMake ≥ 3.14
- Internet access (CMake will fetch `nlohmann/json` and `asio` automatically)
- Python 3 (for the test script)

## Build

```bash
mkdir build && cd build
cmake .. -DUSE_VULNERABLE=OFF   # Safe build
cmake .. -DUSE_VULNERABLE=ON    # Vulnerable build (for testing)
make -j$(nproc)
```

## Run

```bash
./DeepVulnerableEngine config.json
```

A sample safe `config.json`:

```json
{
  "port": 8080,
  "log_file": "engine.log",
  "pool_size": 1048576,
  "jobs": []
}
```

## Enable vulnerabilities

Pass `-DUSE_VULNERABLE=ON` to CMake. This activates all vulnerable code paths
selected by `#ifdef USE_VULNERABLE`.

## Vulnerability overview

| ID | Type | File |
|----|------|------|
| VULN-1 | Integer overflow → heap overflow | memory_pool.cpp |
| VULN-2 | Use‑after‑free via dangling lambda capture | job_queue.cpp |
| VULN-3 | Path traversal via symlink follow | directory_cleaner.cpp |
| VULN-4 | Race condition on memory pool free‑list | memory_pool.cpp |
| VULN-5 | Command injection via incomplete shell sanitizer | pipeline.cpp |
| VULN-6 | Exception safety – double free | resource_handler.cpp |
| INFO | Uninitialized stack padding written to log | info_leak.cpp |

For each vulnerable file, an `_LABELED.cpp` copy is provided with
`// VULN-<n>:` and `// FIX-<n>:` comments.

## Testing with the Python script

`trigger_deep_vulns.py` attempts to exploit each vulnerability.
It launches the engine with crafted configurations and checks for
expected effects (crashes, file creation, data leaks).

Run it from the project root after building with `USE_VULNERABLE=ON`:

```bash
python3 trigger_deep_vulns.py ./build/DeepVulnerableEngine
```

The script will report which vulnerabilities were successfully triggered.

**Warning:** The script may create files in `/tmp` and delete test files.
It is self‑contained and does not harm the system outside `/tmp`.
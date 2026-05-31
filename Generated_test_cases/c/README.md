# DeepVulnerableEngineC

A multi-threaded data processing engine written in C, intentionally containing deep, subtle security vulnerabilities.

## Build

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
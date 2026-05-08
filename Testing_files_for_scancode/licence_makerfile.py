"""
generate_heavy_test_file.py

Creates a LARGE synthetic source-code file
for ScanCode performance testing.

This intentionally generates:
- many comments
- fake licenses
- imports
- classes
- functions
- repeated patterns
- large strings

Goal:
Stress-test ScanCode parsing + license detection.
"""

from pathlib import Path


OUTPUT_FILE = "huge_test_file_500.py"

# Increase this for heavier testing
FUNCTION_COUNT = 50


LICENSE_BLOCK = """
# =========================================================
# MIT License
#
# Copyright (c) 2026 Test Corp
#
# Permission is hereby granted, free of charge,
# to any person obtaining a copy of this software...
#
# Apache License Version 2.0
#
# SPDX-License-Identifier: MIT
# SPDX-License-Identifier: Apache-2.0
# =========================================================
"""


IMPORTS = """
import os
import sys
import json
import random
import hashlib
import threading
import asyncio
import sqlite3
import math
"""


def generate_function(i: int) -> str:
    return f'''
class TestClass{i}:

    def __init__(self):
        self.value = {i}

    def compute(self, x):
        data = []
        for j in range(100):
            value = (x * j + self.value) % 99991
            data.append(value)

        text = "Open source software scanning tool " * 20

        return {{
            "id": {i},
            "sum": sum(data),
            "hash": hashlib.md5(text.encode()).hexdigest()
        }}


def function_{i}(x):
    result = []
    for k in range(200):
        result.append((x + k) ** 2)

    obj = TestClass{i}()

    return obj.compute(sum(result))
'''


# -------------------------------------------------------
# FILE GENERATION
# -------------------------------------------------------

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:

    f.write(LICENSE_BLOCK)
    f.write("\n")
    f.write(IMPORTS)
    f.write("\n")

    for i in range(FUNCTION_COUNT):
        f.write(generate_function(i))

print(f"\nGenerated: {OUTPUT_FILE}")

size_mb = Path(OUTPUT_FILE).stat().st_size / (1024 * 1024)

print(f"File Size: {size_mb:.2f} MB")
print(f"Functions Generated: {FUNCTION_COUNT}")
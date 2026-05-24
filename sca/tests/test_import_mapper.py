from pathlib import Path
from sca.import_mapper import map_imports


def test_python_imports(tmp_path):
    file = tmp_path / "test.py"
    file.write_text("import os\nfrom sys import argv\nimport numpy as np\n")
    result = map_imports([file])
    assert "os" in result
    assert "sys" in result
    assert "numpy" in result
    # line numbers
    assert any(path.endswith("test.py") and lineno == 1 for path, lineno in result["os"])
    assert any(path.endswith("test.py") and lineno == 2 for path, lineno in result["sys"])

def test_javascript_imports(tmp_path):
    file = tmp_path / "test.js"
    file.write_text("import React from 'react';\nconst fs = require('fs');\nimport { useState } from 'react';\n")
    result = map_imports([file])
    assert "react" in result
    assert "fs" in result


def test_java_imports(tmp_path):
    file = tmp_path / "Test.java"
    file.write_text("import java.util.List;\nimport org.apache.commons.lang3.StringUtils;\n")
    result = map_imports([file])
    assert "java" in result
    assert "org" in result


def test_go_imports(tmp_path):
    file = tmp_path / "main.go"
    file.write_text('package main\nimport "fmt"\nimport (\n    "net/http"\n    "github.com/gin-gonic/gin"\n)\n')
    result = map_imports([file])
    assert "fmt" in result
    assert "http" in result
    assert "gin" in result


def test_c_includes(tmp_path):
    file = tmp_path / "program.c"
    file.write_text('#include <stdio.h>\n#include "mylib.h"\n')
    result = map_imports([file])
    assert "stdio" in result
    assert "mylib" in result
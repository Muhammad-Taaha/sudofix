import shutil
import pytest
from pathlib import Path
from sca.scanners import LicenseScanner

MIT_LICENSE_TEXT = """MIT License

Copyright (c) 2023 Some Author

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

@pytest.mark.skipif(
    shutil.which("scancode") is None and shutil.which("scancode.bat") is None,
    reason="scancode CLI not found in PATH"
)
def test_license_scanner_detects_mit(tmp_path):
    # Create a file with MIT license in a temp directory
    file = tmp_path / "LICENSE.txt"
    file.write_text(MIT_LICENSE_TEXT)
    scanner = LicenseScanner()
    findings = scanner.scan_directory(str(tmp_path), file_paths=[file])
    assert len(findings) == 1
    finding = findings[0]
    assert "mit" in finding.license_expression.lower()
    assert "MIT" in finding.spdx_id
    assert finding.confidence >= 0   # scancode may report 0 or 100, both are fine
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch

from sca.binary_fingerprint import (
    is_binary_file,
    extract_strings,
    PseudoDependency,
    BinaryFingerprinter,
)


# ---------------------------------------------------------------------------
# 1. Tests for binary detection (ELF / PE / Mach‑O / text)
# ---------------------------------------------------------------------------
def test_is_binary_elf():
    """Recognise an ELF file by magic bytes."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(b"\x7fELF\x02\x01\x01\x00extra")
        tmp_path = Path(f.name)
    assert is_binary_file(tmp_path) is True
    tmp_path.unlink()


def test_is_binary_pe():
    """Recognise a Windows PE file."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
        f.write(b"MZ\x90\x00extra")
        tmp_path = Path(f.name)
    assert is_binary_file(tmp_path) is True
    tmp_path.unlink()


def test_is_binary_macho():
    """Recognise a Mach‑O file."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(b"\xfe\xed\xfa\xceextra")
        tmp_path = Path(f.name)
    assert is_binary_file(tmp_path) is True
    tmp_path.unlink()


def test_is_binary_text():
    """A plain text file is not binary."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
        f.write("Hello, world!")
        tmp_path = Path(f.name)
    assert is_binary_file(tmp_path) is False
    tmp_path.unlink()


# ---------------------------------------------------------------------------
# 2. Tests for string extraction from a binary
# ---------------------------------------------------------------------------
def test_extract_strings():
    """extract_strings() returns printable strings of minimum length."""
    data = b"abc\x00Hello World\x00\x00\x00\x01\x02"
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(data)
        tmp_path = Path(f.name)
    strings = extract_strings(tmp_path, min_length=4)
    # "abc" is length 3 → ignored, "Hello World" length 11 → included
    assert "Hello World" in strings
    assert "abc" not in strings
    tmp_path.unlink()


# ---------------------------------------------------------------------------
# 3. Tests for the full fingerprinter (pseudo‑dependency detection)
# ---------------------------------------------------------------------------

# Unique marker bytes to avoid cache collisions between tests
UNIQUE1 = b"\x00\x11\x22\x33"
UNIQUE2 = b"\x00\x44\x55\x66"
UNIQUE3 = b"\x00\x77\x88\x99"

KNOWN_LIBRARY_PATTERNS = {
    "libpng": r"libpng\s+(?:version\s+)?(\d+\.\d+\.\d+)",
    "openssl": r"openssl\s+(\d+\.\d+\.\d+)",
}

def test_fingerprinter_skips_unknown_strings():
    """Strings that don't match any pattern are ignored."""
    data = b"MZ\x90\x00" + b"some random string\x00hello world\x00" + UNIQUE2
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
        f.write(data)
        tmp_path = Path(f.name)
    fingerprinter = BinaryFingerprinter(known_patterns={"libssl": r"libssl\s+(\d+\.\d+)"})
    results = fingerprinter.fingerprint(tmp_path)
    assert results == []
    tmp_path.unlink()


def test_fingerprinter_cache():
    """Second call returns cached result without re‑scanning."""
    content = (
        b"\x7fELF\x02\x01\x01\x00"
        b"some padding\x00"
        b"libpng version 1.6.37\x00"
        b"another string\x00"
        b"openssl 3.0.0\x00"
        + UNIQUE3
    )
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(content)
        tmp_path = Path(f.name)
    fingerprinter = BinaryFingerprinter(
        known_patterns=KNOWN_LIBRARY_PATTERNS,
        cache_dir=str(tmp_path.parent / "cache"),
    )
    first = fingerprinter.fingerprint(tmp_path)
    # Patch internal scan method to ensure it's not called again
    with patch.object(fingerprinter, "_scan_file", wraps=fingerprinter._scan_file) as mock_scan:
        second = fingerprinter.fingerprint(tmp_path)
        mock_scan.assert_not_called()   # cached
    assert first == second
    tmp_path.unlink()


# ---------------------------------------------------------------------------
# 4. Test for error handling on non‑binary files
# ---------------------------------------------------------------------------
def test_fingerprinter_non_binary_skips():
    """Non‑binary files produce an empty list (not an error)."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
        f.write("just text")
        tmp_path = Path(f.name)
    fingerprinter = BinaryFingerprinter(known_patterns=KNOWN_LIBRARY_PATTERNS)
    results = fingerprinter.fingerprint(tmp_path)
    assert results == []
    tmp_path.unlink()
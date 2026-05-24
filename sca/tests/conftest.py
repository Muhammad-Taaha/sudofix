import os
import pytest
from pathlib import Path
from typing import Generator

from sca.utils import configure_logging


@pytest.fixture(autouse=True, scope="session")
def set_offline_mode():
    """Ensure all tests run offline – no network requests."""
    os.environ["SCA_OFFLINE"] = "1"
    yield


@pytest.fixture(autouse=True)
def setup_logging_fixture():
    """Configure logging for every test."""
    configure_logging(level="DEBUG")


@pytest.fixture
def fake_project(tmp_path) -> Generator[Path, None, None]:
    """Create a tiny fake project with a few files."""
    base = tmp_path / "fake_project"
    base.mkdir()
    (base / ".gitignore").write_text("*.pyc\n/dist\n")
    (base / "main.py").write_text("# hello\nprint('world')\n")
    (base / "script.js").write_text("console.log('hi');\n")
    (base / "readme.txt").write_text("This is a text file.\n")
    (base / "node_modules").mkdir()
    (base / "node_modules" / "package.json").write_text("{}")
    yield base
import pytest
from pathlib import Path
from sca.resolver.plugins.ruby import RubyResolver

GEMFILE_LOCK = """
GEM
  remote: https://rubygems.org/
  specs:
    rails (6.1.7.3)
      actioncable (= 6.1.7.3)
      actionmailbox (= 6.1.7.3)
    actioncable (6.1.7.3)
    actionmailbox (6.1.7.3)
    nokogiri (1.14.0)

PLATFORMS
  ruby

DEPENDENCIES
  rails (~> 6.1)
"""

def test_resolves_all_gems():
    project = Path("/tmp/test")
    project.mkdir(parents=True, exist_ok=True)
    (project / "Gemfile.lock").write_text(GEMFILE_LOCK)
    resolver = RubyResolver()
    packages = resolver.resolve(str(project))
    names = {p.name for p in packages}
    assert "rails" in names
    assert "nokogiri" in names
    assert len(packages) == 4

def test_version_extraction():
    project = Path("/tmp/test2")
    project.mkdir(parents=True, exist_ok=True)
    (project / "Gemfile.lock").write_text(GEMFILE_LOCK)
    resolver = RubyResolver()
    packages = resolver.resolve(str(project))
    nokogiri = next(p for p in packages if p.name == "nokogiri")
    assert nokogiri.version == "1.14.0"

def test_no_gemfile_lock_empty():
    project = Path("/tmp/empty")
    project.mkdir(parents=True, exist_ok=True)
    resolver = RubyResolver()
    assert resolver.resolve(str(project)) == []

def test_can_handle():
    resolver = RubyResolver()
    assert resolver.can_handle(["some/path/Gemfile.lock"])
    assert not resolver.can_handle(["package.json"])

def test_duplicate_versions_merged():
    text = """
GEM
  specs:
    rake (13.0.6)
    rake (13.0.6)
"""
    project = Path("/tmp/dup")
    project.mkdir(parents=True, exist_ok=True)
    (project / "Gemfile.lock").write_text(text)
    resolver = RubyResolver()
    packages = resolver.resolve(str(project))
    assert len(packages) == 1
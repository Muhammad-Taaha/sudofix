import sqlite3
import pytest
from pathlib import Path
from sca.streaming_writer import StreamingWriter
from sca.exceptions import SCAError, DependencyResolutionError, ScanCodeError, NetworkError


def test_exceptions_inheritance():
    assert issubclass(DependencyResolutionError, SCAError)
    assert issubclass(ScanCodeError, SCAError)
    assert issubclass(NetworkError, SCAError)


def test_streaming_writer(tmp_path):
    db_path = tmp_path / "output.db"
    writer = StreamingWriter(db_path)
    writer.write_finding("proj1", "license", {"spdx": "MIT"})
    writer.write_many("proj1", "vulnerabilities", [{"id": "CVE-123"}, {"id": "CVE-456"}])
    writer.close()

    conn = sqlite3.connect(str(db_path))
    rows = conn.execute("SELECT category, data_json FROM findings").fetchall()
    assert len(rows) == 3
    categories = {r[0] for r in rows}
    assert "license" in categories
    assert "vulnerabilities" in categories
    conn.close()


def test_network_error_retry(monkeypatch):
    import sca.outdated_checker                          # needed for correct patch target
    from sca.outdated_checker import OutdatedChecker
    from sca.resolver.base import ResolvedPackage
    import requests

    # conftest sets SCA_OFFLINE=1 for all tests; unset it so the checker
    # actually reaches the (mocked) network call.
    monkeypatch.delenv("SCA_OFFLINE", raising=False)

    call_count = 0

    def mock_get(url, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise requests.RequestException("fail")

        class MockResp:
            status_code = 200

            def json(self):
                return {"info": {"version": "2.0"}}

            def raise_for_status(self):
                pass

        return MockResp()

    # Must patch the `requests` object inside the sca.outdated_checker module,
    # not the top-level `requests` module — otherwise the already-imported
    # reference inside outdated_checker is never replaced.
    monkeypatch.setattr(sca.outdated_checker.requests, "get", mock_get)

    checker = OutdatedChecker()
    pkgs = [ResolvedPackage(name="test", version="1.0", ecosystem="pypi")]
    results = checker.check(pkgs)
    assert call_count == 3
    assert len(results) == 1
    assert results[0].latest_version == "2.0"
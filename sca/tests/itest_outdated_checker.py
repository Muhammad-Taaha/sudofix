import pytest
from sca.outdated_checker import OutdatedChecker
from sca.resolver.base import ResolvedPackage


def test_outdated_checker(monkeypatch):
    # conftest sets SCA_OFFLINE=1 for all tests; unset it here so the
    # checker actually reaches the (mocked) network call.
    monkeypatch.delenv("SCA_OFFLINE", raising=False)

    # Mock requests to avoid real API calls
    def mock_get(url, **kwargs):
        class MockResp:
            status_code = 200

            def json(self):
                if "pypi.org" in url:
                    return {"info": {"version": "2.0.0"}}
                elif "npmjs" in url:
                    return {"version": "6.0.0"}

            def raise_for_status(self):
                pass

        return MockResp()

    import sca.outdated_checker
    monkeypatch.setattr(sca.outdated_checker.requests, "get", mock_get)

    checker = OutdatedChecker()
    pkgs = [
        ResolvedPackage(name="requests", version="1.0.0", ecosystem="pypi"),
        ResolvedPackage(name="lodash", version="5.0.0", ecosystem="npm"),
    ]
    findings = checker.check(pkgs)
    assert len(findings) == 2
    assert findings[0].latest_version == "2.0.0"
    assert findings[1].latest_version == "6.0.0"
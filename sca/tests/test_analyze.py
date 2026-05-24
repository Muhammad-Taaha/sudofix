from sca import analyze
import pytest
import json


def test_analyze_on_empty_project(fake_project):
    """Analyze a simple project with no manifests – should still succeed."""
    result = analyze(str(fake_project))
    assert result["status"] == "ok"
    assert len(result["sub_projects"]) == 1
    sub = result["sub_projects"][0]
    assert sub["packages"] == []


def test_analyze_with_npm_manifest(tmp_path):
    """Analyze a project that contains a package.json + lockfile."""
    import json
    project = tmp_path / "npm_project"
    project.mkdir()
    (project / "package.json").write_text(
        json.dumps({"name": "test", "dependencies": {"chalk": "^5.0.0"}})
    )
    (project / "package-lock.json").write_text(
        json.dumps({
            "lockfileVersion": 2,
            "packages": {
                "": {"name": "test", "dependencies": {"chalk": "^5.0.0"}},
                "node_modules/chalk": {"version": "5.3.0"}
            }
        })
    )
    result = analyze(str(project))
    sub = result["sub_projects"][0]
    assert len(sub["packages"]) >= 1
    chalk = next(p for p in sub["packages"] if p["name"] == "chalk")
    assert chalk["version"] == "5.3.0"


@pytest.mark.parametrize("manifest_type", ["npm", "pypi", "maven", "go"])
def test_analyze_various_manifests(manifest_type, tmp_path):
    """Quick smoke tests across different manifest types; don't require exact versions.

    The goal is to ensure `analyze` runs and returns a sensible `packages` list
    for common ecosystems without asserting brittle version resolution.
    """
    project = tmp_path / f"{manifest_type}_project"
    project.mkdir()

    if manifest_type == "npm":
        (project / "package.json").write_text(
            json.dumps({"name": "test", "dependencies": {"chalk": "^5.0.0"}})
        )
        (project / "package-lock.json").write_text(
            json.dumps({
                "lockfileVersion": 2,
                "packages": {
                    "": {"name": "test", "dependencies": {"chalk": "^5.0.0"}},
                    "node_modules/chalk": {"version": "5.3.0"}
                }
            })
        )

    elif manifest_type == "pypi":
        (project / "requirements.txt").write_text("requests==2.31.0\n")

    elif manifest_type == "maven":
        # Minimal POM with a common test dependency
        (project / "pom.xml").write_text(
            """
            <project xmlns=\"http://maven.apache.org/POM/4.0.0\">
              <modelVersion>4.0.0</modelVersion>
              <groupId>com.example</groupId>
              <artifactId>demo</artifactId>
              <version>1.0.0</version>
              <dependencies>
                <dependency>
                  <groupId>junit</groupId>
                  <artifactId>junit</artifactId>
                  <version>4.12</version>
                </dependency>
              </dependencies>
            </project>
            """
        )

    elif manifest_type == "go":
        (project / "go.mod").write_text("module example.com/test\n\nrequire github.com/stretchr/testify v1.7.0\n")

    result = analyze(str(project))
    assert result["status"] == "ok"
    assert len(result["sub_projects"]) >= 1
    sub = result["sub_projects"][0]
    assert isinstance(sub.get("packages"), list)

    # Prefer non-brittle checks: ensure at least the ecosystem produced a packages list.
    # When a manifest explicitly declares a dependency, expect it to be discovered.
    if manifest_type == "npm":
        assert any(p.get("name") == "chalk" for p in sub["packages"])
    elif manifest_type == "pypi":
        assert any("requests" in (p.get("name") or "") for p in sub["packages"])
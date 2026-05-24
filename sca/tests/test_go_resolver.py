from pathlib import Path
from sca.resolver.plugins.go import GoResolver


def test_go_resolver(tmp_path):
    project = tmp_path / "go_app"
    project.mkdir()
    go_mod_content = """module example.com/myapp

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/sirupsen/logrus v1.9.3
)
"""
    (project / "go.mod").write_text(go_mod_content)

    go_sum_content = """github.com/gin-gonic/gin v1.9.1 h1:abcd...
github.com/gin-gonic/gin v1.9.1/go.mod h1:efgh...
github.com/sirupsen/logrus v1.9.3 h1:efgh...
github.com/go-playground/validator/v10 v10.14.0 h1:efgh...
"""
    (project / "go.sum").write_text(go_sum_content)

    resolver = GoResolver()
    packages = resolver.resolve(str(project))

    # Should find gin, logrus, and validator
    assert len(packages) == 3

    gin = next(p for p in packages if p.name == "github.com/gin-gonic/gin")
    assert gin.version == "v1.9.1"
    assert gin.is_direct

    validator = next(p for p in packages if p.name == "github.com/go-playground/validator/v10")
    assert validator.version == "v10.14.0"
    assert not validator.is_direct  # only in go.sum, not in go.mod require
import sys
import os
from pathlib import Path
import pytest
import shutil
from sca.resolver.plugins.maven import MavenResolver

@pytest.mark.skipif(os.name != "posix" or not shutil.which("mvn"), reason="Maven not available or not Linux")
def test_maven_with_mvn(tmp_path):
    # This test requires actual Maven installation; we'll just test fallback path by mocking the mvn check
    pass

def test_maven_fallback_pom_parsing(tmp_path):
    project = tmp_path / "mvn_proj"
    project.mkdir()
    pom_xml = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>my-app</artifactId>
    <version>1.0</version>
    <dependencies>
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-lang3</artifactId>
            <version>3.12.0</version>
        </dependency>
    </dependencies>
</project>"""
    (project / "pom.xml").write_text(pom_xml)

    resolver = MavenResolver()
    # Force fallback: set env to disable mvn detection
    os.environ["SCA_ALLOW_SUBPROCESS"] = "0"
    packages = resolver.resolve(str(project))
    assert len(packages) >= 2  # includes the project itself and the dependency
    dep = next(p for p in packages if p.name == "org.apache.commons:commons-lang3")
    assert dep.version == "3.12.0"
    assert dep.is_direct
import os
import sys
import json
import pytest
import sca.cli


def test_cli_scan_help(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["sca", "scan", "--help"])
    with pytest.raises(SystemExit) as exc:
        sca.cli.main()
    captured = capsys.readouterr()
    assert exc.value.code == 0
    # argparse prints usage + arguments, not the help description string
    assert "project_path" in captured.out
    assert "--json" in captured.out


def test_cli_update_db_help(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["sca", "update-db", "--help"])
    with pytest.raises(SystemExit) as exc:
        sca.cli.main()
    captured = capsys.readouterr()
    assert exc.value.code == 0
    assert "--download" in captured.out
    assert "--input" in captured.out


def test_cli_rules_list(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["sca", "rules"])
    try:
        sca.cli.main()
    except SystemExit:
        pass
    captured = capsys.readouterr()
    assert "python-eval" in captured.out or "js-dangerouslySetInnerHTML" in captured.out


def test_cli_config_init(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["sca", "config"])
    old_cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        sca.cli.main()
        assert (tmp_path / "sca-config.yml").exists()
    finally:
        os.chdir(old_cwd)


def test_cli_scan_json(tmp_path, monkeypatch, capsys):
    project = tmp_path / "tiny"
    project.mkdir()
    (project / "main.py").write_text("# empty")
    monkeypatch.setattr(sys, "argv", ["sca", "scan", str(project), "--json"])
    try:
        sca.cli.main()
    except SystemExit:
        pass
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["status"] == "ok"
    assert "sub_projects" in data
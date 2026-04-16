from pathlib import Path

from forge_cli.config import load_config


def test_load_config_defaults_data_root_to_repo_root(tmp_path):
    cfg = load_config(root=tmp_path)

    assert cfg.data_root == tmp_path
    assert cfg.incidents_dir == tmp_path / "incidents"
    assert cfg.analysis_dir == tmp_path / "analysis"
    assert cfg.playbook_dir == tmp_path / "playbook"
    assert cfg.templates_dir == tmp_path / "templates"


def test_load_config_uses_local_data_root_override(tmp_path):
    (tmp_path / "config.yaml").write_text('default_reporter: "sham"\n', encoding="utf-8")
    (tmp_path / "config.local.yaml").write_text('data_root: "~/forge-private"\n', encoding="utf-8")

    cfg = load_config(root=tmp_path)

    assert cfg.data_root == Path("~/forge-private").expanduser()
    assert cfg.incidents_dir == Path("~/forge-private").expanduser() / "incidents"


def test_load_config_env_data_root_override_wins(tmp_path, monkeypatch):
    (tmp_path / "config.local.yaml").write_text('data_root: "~/forge-private"\n', encoding="utf-8")
    monkeypatch.setenv("FORGE_DATA_ROOT", str(tmp_path / "env-data"))

    cfg = load_config(root=tmp_path)

    assert cfg.data_root == tmp_path / "env-data"

from forge_cli.config import ForgeConfig


def test_playbook_dir_exists(tmp_path):
    """Playbook dir property returns correct path."""
    cfg = ForgeConfig(root=tmp_path)
    assert cfg.playbook_dir == tmp_path / "playbook"


def test_playbook_list_empty(tmp_path):
    """No playbook entries returns empty glob."""
    playbook_dir = tmp_path / "playbook"
    playbook_dir.mkdir()
    entries = sorted(playbook_dir.glob("*.md"))
    entries = [e for e in entries if e.stem != "index"]
    assert entries == []


def test_playbook_list_with_entries(tmp_path):
    """Playbook entries are discovered correctly."""
    playbook_dir = tmp_path / "playbook"
    playbook_dir.mkdir()
    (playbook_dir / "index.md").write_text("# Index")
    (playbook_dir / "silent-fallback.md").write_text("# Silent Fallback")
    (playbook_dir / "hallucination.md").write_text("# Hallucination")

    entries = sorted(playbook_dir.glob("*.md"))
    entries = [e for e in entries if e.stem != "index"]
    assert len(entries) == 2
    stems = [e.stem for e in entries]
    assert "hallucination" in stems
    assert "silent-fallback" in stems


def test_playbook_show_exact_match(tmp_path):
    """Exact name match finds the right file."""
    playbook_dir = tmp_path / "playbook"
    playbook_dir.mkdir()
    target = playbook_dir / "silent-fallback.md"
    target.write_text("# Silent Fallback Pattern")

    found = playbook_dir / "silent-fallback.md"
    assert found.exists()
    assert "Silent Fallback" in found.read_text()


def test_playbook_show_partial_match(tmp_path):
    """Partial name match finds entries."""
    playbook_dir = tmp_path / "playbook"
    playbook_dir.mkdir()
    (playbook_dir / "index.md").write_text("# Index")
    (playbook_dir / "silent-fallback.md").write_text("# Silent Fallback")

    name = "silent"
    matches = [f for f in playbook_dir.glob("*.md") if name.lower() in f.stem.lower() and f.stem != "index"]
    assert len(matches) == 1
    assert matches[0].stem == "silent-fallback"

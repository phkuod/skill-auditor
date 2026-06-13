# tests/test_inventory.py
from pathlib import Path

from skill_auditor.inventory import SkillFile, classify, inventory_skill

CLEAN = Path(__file__).parent / "fixtures" / "clean_skill"
MAL = Path(__file__).parent / "fixtures" / "malicious_skill"


def test_classify_known_kinds():
    assert classify("SKILL.md") == "skill_md"
    assert classify("scripts/x.py") == "python"
    assert classify("scripts/x.sh") == "shell"
    assert classify("references/a.md") == "markdown"
    assert classify("data/blob.png") == "asset"


def test_inventory_returns_relative_paths_and_text():
    files = inventory_skill(CLEAN)
    rels = {f.relpath for f in files}
    assert "SKILL.md" in rels
    assert "scripts/format_greeting.py" in rels
    skill_md = next(f for f in files if f.relpath == "SKILL.md")
    assert "Greet Formatter" in skill_md.text


def test_inventory_skips_pycache():
    files = inventory_skill(MAL)
    assert all("__pycache__" not in f.relpath for f in files)


def test_skillfile_text_none_for_binary(tmp_path):
    (tmp_path / "a.png").write_bytes(b"\x89PNG\x00\x01\x02")
    files = inventory_skill(tmp_path)
    png = next(f for f in files if f.relpath == "a.png")
    assert png.kind == "asset"
    assert png.text is None

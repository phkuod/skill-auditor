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


def test_oversized_text_file_records_skip_reason(tmp_path):
    (tmp_path / "big.py").write_text("# " + "x" * 1_000_001)
    files = inventory_skill(tmp_path)
    big = next(f for f in files if f.relpath == "big.py")
    assert big.text is None
    assert big.skip_reason == "too_large"


def test_fully_read_file_has_no_skip_reason(tmp_path):
    (tmp_path / "ok.py").write_text("x = 1\n")
    files = inventory_skill(tmp_path)
    ok = next(f for f in files if f.relpath == "ok.py")
    assert ok.skip_reason is None


def test_binary_asset_is_not_a_coverage_gap(tmp_path):
    (tmp_path / "a.png").write_bytes(b"\x89PNG\x00")
    files = inventory_skill(tmp_path)
    png = next(f for f in files if f.relpath == "a.png")
    assert png.skip_reason is None  # intentional skip, not a gap


def test_disguised_python_asset_is_reclassified(tmp_path):
    # payload.py renamed to .txt must NOT escape the Python scanner.
    (tmp_path / "evil.txt").write_text("import os\nos.system('rm -rf /tmp/x')\n")
    files = inventory_skill(tmp_path)
    evil = next(f for f in files if f.relpath == "evil.txt")
    assert evil.kind == "python"
    assert evil.text is not None


def test_shell_shebang_asset_is_reclassified(tmp_path):
    (tmp_path / "run.txt").write_text("#!/bin/bash\nrm -rf /tmp/x\n")
    files = inventory_skill(tmp_path)
    run = next(f for f in files if f.relpath == "run.txt")
    assert run.kind == "shell"


def test_prose_text_stays_asset(tmp_path):
    (tmp_path / "notes.txt").write_text("This is a note, not code. Read me!\n")
    files = inventory_skill(tmp_path)
    notes = next(f for f in files if f.relpath == "notes.txt")
    assert notes.kind == "asset"

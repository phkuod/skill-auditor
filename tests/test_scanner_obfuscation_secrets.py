# tests/test_scanner_obfuscation_secrets.py
from pathlib import Path

from skill_auditor.inventory import inventory_skill
from skill_auditor.scanners import obfuscation_secrets as osec

MAL = Path(__file__).parent / "fixtures" / "malicious_skill"
CLEAN = Path(__file__).parent / "fixtures" / "clean_skill"


def test_flags_hardcoded_aws_key():
    findings = osec.scan(inventory_skill(MAL))
    assert any(f.category == "SECRETS" for f in findings)


def test_flags_base64_decode_exec_combo():
    findings = osec.scan(inventory_skill(MAL))
    assert any(f.category == "OBFUSCATION" for f in findings)


def test_flags_zero_width_characters(tmp_path):
    (tmp_path / "SKILL.md").write_text("hello​world with hidden‌ chars", encoding="utf-8")
    findings = osec.scan(inventory_skill(tmp_path))
    assert any(f.rule_id == "OB-ZEROWIDTH-001" for f in findings)


def test_flags_mixed_script_homoglyph(tmp_path):
    # 'pаssword' contains a Cyrillic 'а' (U+0430) mixed with ASCII letters.
    (tmp_path / "a.py").write_text("pаssword = lookup()\n", encoding="utf-8")
    assert any(f.rule_id == "OB-HOMOGLYPH-001" for f in osec.scan(inventory_skill(tmp_path)))


def test_flags_abnormally_long_line(tmp_path):
    (tmp_path / "b.py").write_text("blob = '" + "A" * 2100 + "'\n")
    assert any(f.rule_id == "OB-LONGLINE-001" for f in osec.scan(inventory_skill(tmp_path)))


def test_flags_rot13_decode(tmp_path):
    (tmp_path / "c.py").write_text("import codecs\ncodecs.decode(payload, 'rot13')\n")
    assert any(f.rule_id == "OB-B64EXEC-001" for f in osec.scan(inventory_skill(tmp_path)))


def test_normal_ascii_code_has_no_obfuscation_findings(tmp_path):
    (tmp_path / "d.py").write_text("name = 'Ada'\nprint(name)\n")
    assert osec.scan(inventory_skill(tmp_path)) == []


def test_clean_skill_is_silent():
    assert osec.scan(inventory_skill(CLEAN)) == []

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


def test_clean_skill_is_silent():
    assert osec.scan(inventory_skill(CLEAN)) == []

# tests/test_scanner_frontmatter.py
from pathlib import Path

from skill_auditor.inventory import inventory_skill
from skill_auditor.scanners import frontmatter

MAL = Path(__file__).parent / "fixtures" / "malicious_skill"
CLEAN = Path(__file__).parent / "fixtures" / "clean_skill"


def test_flags_wildcard_tools_and_hooks():
    findings = frontmatter.scan(inventory_skill(MAL))
    rules = {f.rule_id for f in findings}
    assert "FM-WILDCARD-001" in rules     # allowed-tools: ["*"]
    assert "FM-HOOK-001" in rules         # hooks present
    assert all(f.category == "OVER_PERMISSION" for f in findings)


def test_clean_frontmatter_is_silent():
    assert frontmatter.scan(inventory_skill(CLEAN)) == []

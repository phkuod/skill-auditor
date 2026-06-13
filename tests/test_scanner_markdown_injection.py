# tests/test_scanner_markdown_injection.py
from pathlib import Path

from skill_auditor.inventory import inventory_skill
from skill_auditor.models import Severity
from skill_auditor.scanners import markdown_injection

MAL = Path(__file__).parent / "fixtures" / "malicious_skill"
INJ = Path(__file__).parent / "fixtures" / "injection_skill"
CLEAN = Path(__file__).parent / "fixtures" / "clean_skill"


def test_flags_ignore_previous_instructions():
    findings = markdown_injection.scan(inventory_skill(MAL))
    assert any(f.category == "PROMPT_INJECTION" for f in findings)
    assert any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)


def test_flags_injection_skill_targeting_the_auditor():
    findings = markdown_injection.scan(inventory_skill(INJ))
    assert any(f.rule_id.startswith("MD-INJECT") for f in findings)


def test_clean_skill_is_silent():
    assert markdown_injection.scan(inventory_skill(CLEAN)) == []

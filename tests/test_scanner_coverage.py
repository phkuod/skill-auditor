# tests/test_scanner_coverage.py
from pathlib import Path

from skill_auditor.inventory import SkillFile
from skill_auditor.models import Severity
from skill_auditor.scanners import coverage


def _sf(kind: str, skip_reason: str | None) -> SkillFile:
    return SkillFile(path=Path("x"), relpath="big.py", kind=kind, text=None, skip_reason=skip_reason)


def test_flags_unscanned_text_file():
    findings = coverage.scan([_sf("python", "too_large")])
    assert len(findings) == 1
    assert findings[0].rule_id == "AUDIT-COVERAGE-001"
    assert findings[0].category == "AUDIT_COVERAGE"
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].file == "big.py"


def test_silent_when_file_fully_read():
    assert coverage.scan([_sf("python", None)]) == []


def test_ignores_binary_assets():
    assert coverage.scan([_sf("asset", None)]) == []

# tests/test_scanner_shell.py
from pathlib import Path

from skill_auditor.inventory import inventory_skill
from skill_auditor.scanners import shell

MAL = Path(__file__).parent / "fixtures" / "malicious_skill"
CLEAN = Path(__file__).parent / "fixtures" / "clean_skill"


def test_flags_rm_rf_and_curl_pipe_bash():
    findings = shell.scan(inventory_skill(MAL))
    cats = {f.category for f in findings}
    assert "DESTRUCTIVE" in cats         # rm -rf
    assert "RCE_SUPPLY_CHAIN" in cats     # curl | bash
    assert all(f.line is not None for f in findings)


def test_clean_skill_has_no_shell_findings():
    assert shell.scan(inventory_skill(CLEAN)) == []

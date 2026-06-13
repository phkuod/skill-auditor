# tests/test_scanner_python_ast.py
from pathlib import Path

from skill_auditor.inventory import inventory_skill
from skill_auditor.models import Severity
from skill_auditor.scanners import python_ast

CLEAN = Path(__file__).parent / "fixtures" / "clean_skill"
MAL = Path(__file__).parent / "fixtures" / "malicious_skill"


def _rule_ids(findings):
    return {f.rule_id for f in findings}


def test_flags_eval_subprocess_network_and_secret_read_in_malicious():
    findings = python_ast.scan(inventory_skill(MAL))
    cats = {f.category for f in findings}
    assert "RCE_SUPPLY_CHAIN" in cats          # eval(...)
    assert "EXFILTRATION" in cats              # requests.post / read ~/.ssh
    assert any(f.severity == Severity.CRITICAL for f in findings)
    assert all(f.line is not None for f in findings)
    assert all(f.file.endswith(".py") for f in findings)


def test_clean_skill_has_no_python_findings():
    assert python_ast.scan(inventory_skill(CLEAN)) == []


def test_handles_syntax_error_without_crashing(tmp_path):
    (tmp_path / "broken.py").write_text("def (:\n")
    from skill_auditor.inventory import inventory_skill as inv
    findings = python_ast.scan(inv(tmp_path))
    # A parse failure is itself reported (can't analyze => suspicious), not a crash.
    assert any(f.rule_id == "PY-PARSE-001" for f in findings)

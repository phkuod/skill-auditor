# tests/test_models.py
import pytest
from pydantic import ValidationError

from skill_auditor.models import AuditReport, Finding, Severity, Source


def _finding(**kw):
    base = dict(
        rule_id="PY-EXEC-001", category="RCE_SUPPLY_CHAIN", severity=Severity.CRITICAL,
        title="eval() call", file="scripts/x.py", line=3, evidence="eval(data)",
        explanation="executes arbitrary code", remediation="remove eval", source=Source.STATIC,
    )
    base.update(kw)
    return Finding(**base)


def test_finding_defaults_confidence_to_one():
    assert _finding().confidence == 1.0


def test_severity_values_are_lowercase_strings():
    assert Severity.CRITICAL.value == "critical"
    assert Severity.LOW.value == "low"


def test_finding_rejects_empty_rule_id():
    with pytest.raises(ValidationError):
        _finding(rule_id="")


def test_audit_report_roundtrips_json():
    report = AuditReport(
        skill_name="demo", skill_path="/tmp/demo", verdict="block",
        findings=[_finding()], counts={"critical": 1}, llm_used=False, notes=[],
    )
    dumped = report.model_dump_json()
    assert '"verdict":"block"' in dumped
    assert AuditReport.model_validate_json(dumped).findings[0].rule_id == "PY-EXEC-001"

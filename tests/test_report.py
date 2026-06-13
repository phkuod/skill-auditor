# tests/test_report.py
from skill_auditor.models import Finding, Severity, Source
from skill_auditor.report import build_report, compute_verdict, verdict_exit_code


def _f(sev):
    return Finding(rule_id="X", category="C", severity=sev, title="t", file="a.py")


def test_verdict_block_on_critical():
    assert compute_verdict([_f(Severity.CRITICAL), _f(Severity.LOW)]) == "block"


def test_verdict_warn_on_high_only():
    assert compute_verdict([_f(Severity.HIGH), _f(Severity.LOW)]) == "warn"


def test_verdict_pass_when_no_high_or_critical():
    assert compute_verdict([_f(Severity.LOW)]) == "pass"
    assert compute_verdict([]) == "pass"


def test_build_report_counts_by_severity():
    report = build_report("demo", "/tmp/demo", [_f(Severity.CRITICAL), _f(Severity.LOW)],
                          llm_used=False, notes=[])
    assert report.verdict == "block"
    assert report.counts["critical"] == 1
    assert report.counts["low"] == 1


def test_exit_codes():
    assert verdict_exit_code("pass", fail_on="critical") == 0
    assert verdict_exit_code("block", fail_on="critical") == 2
    assert verdict_exit_code("warn", fail_on="critical") == 0   # below threshold
    assert verdict_exit_code("warn", fail_on="high") == 1

# tests/test_report.py
from skill_auditor.models import Finding, Severity, Source
from skill_auditor.report import (
    build_report,
    compute_verdict,
    dedupe_findings,
    verdict_exit_code,
)


def _f(sev):
    return Finding(rule_id="X", category="C", severity=sev, title="t", file="a.py")


def _static(category, file, line):
    return Finding(rule_id="S", category=category, severity=Severity.CRITICAL, title="s",
                   file=file, line=line, source=Source.STATIC)


def _llm(category, file, line):
    return Finding(rule_id="LLM-001", category=category, severity=Severity.HIGH, title="l",
                   file=file, line=line, source=Source.LLM, confidence=0.7)


def test_dedupe_drops_llm_finding_matching_static():
    static = _static("RCE_SUPPLY_CHAIN", "setup.sh", 3)
    out = dedupe_findings([static, _llm("RCE_SUPPLY_CHAIN", "setup.sh", 3)])
    assert out == [static]


def test_dedupe_drops_llm_finding_with_no_line_matching_static_file_category():
    static = _static("PROMPT_INJECTION", "SKILL.md", 9)
    out = dedupe_findings([static, _llm("PROMPT_INJECTION", "SKILL.md", None)])
    assert out == [static]


def test_dedupe_keeps_distinct_llm_finding():
    static = _static("RCE_SUPPLY_CHAIN", "a.py", 1)
    llm = _llm("PROMPT_INJECTION", "SKILL.md", 9)
    assert len(dedupe_findings([static, llm])) == 2


def test_dedupe_drops_exact_duplicates():
    f = _f(Severity.LOW)
    assert dedupe_findings([f, f]) == [f]


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

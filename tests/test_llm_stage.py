# tests/test_llm_stage.py
from pathlib import Path

from pydantic_ai.messages import ModelResponse, ToolCallPart
from pydantic_ai.models.function import FunctionModel

from skill_auditor.inventory import SkillFile, inventory_skill
from skill_auditor.llm.agent import SYSTEM_PROMPT, build_audit_agent
from skill_auditor.llm.stages import (
    MAX_FILE_CHARS,
    LlmFindings,
    adjudicate,
    semantic_scan,
    truncated_for_llm,
)
from skill_auditor.models import Finding, Severity, Source

INJ = Path(__file__).parent / "fixtures" / "injection_skill"


def _critical():
    return Finding(rule_id="PY-EXEC-001", category="RCE_SUPPLY_CHAIN", severity=Severity.CRITICAL,
                   title="eval()", file="x.py", line=1, source=Source.STATIC, confidence=1.0)


def test_adjudicate_updates_confidence_but_not_severity():
    def fn(messages, info):
        from skill_auditor.llm.stages import _Adjudication
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name,
            _Adjudication(items=[{"index": 0, "confidence": 0.3, "note": "demo only"}]).model_dump())])
    agent = build_audit_agent(model=FunctionModel(fn))
    out, ran = adjudicate(agent, [_critical()], [])
    assert ran is True
    assert out[0].confidence == 0.3
    assert out[0].severity == Severity.CRITICAL  # advisory only — severity untouched


def test_adjudicate_degrades_on_model_error_leaving_findings_unchanged():
    findings = [_critical()]

    def boom(messages, info):
        raise RuntimeError("models down")
    agent = build_audit_agent(model=FunctionModel(boom))
    out, ran = adjudicate(agent, findings, [])
    assert ran is False
    assert out == findings


def test_adjudicate_with_no_findings_is_a_noop():
    agent = build_audit_agent(model=FunctionModel(lambda m, i: None))
    out, ran = adjudicate(agent, [], [])
    assert out == [] and ran is False


def test_truncated_for_llm_lists_oversized_files():
    big = SkillFile(path=Path("x"), relpath="big.md", kind="markdown",
                    text="a" * (MAX_FILE_CHARS + 1))
    small = SkillFile(path=Path("y"), relpath="ok.md", kind="markdown", text="a")
    assert truncated_for_llm([big, small]) == ["big.md"]


def test_system_prompt_frames_content_as_untrusted():
    low = SYSTEM_PROMPT.lower()
    assert "untrusted" in low
    assert "do not" in low or "never" in low


def test_semantic_scan_returns_findings_marked_llm():
    payload = LlmFindings(findings=[dict(
        rule_id="LLM-INJECT-001", category="PROMPT_INJECTION", severity="critical",
        title="auditor-directed injection", file="SKILL.md", line=9,
        evidence="Ignore previous instructions", explanation="targets the auditor",
        remediation="reject skill", confidence=0.9)])

    def fn(messages, info):
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, payload.model_dump())])

    agent = build_audit_agent(model=FunctionModel(fn))
    findings, ran = semantic_scan(agent, inventory_skill(INJ))
    assert ran is True
    assert findings and findings[0].source == Source.LLM
    assert findings[0].severity == Severity.CRITICAL


def test_semantic_scan_reports_not_ran_on_model_error():
    def boom(messages, info):
        raise RuntimeError("all models rate-limited")

    agent = build_audit_agent(model=FunctionModel(boom))
    findings, ran = semantic_scan(agent, inventory_skill(INJ))
    assert findings == []
    assert ran is False


def test_semantic_scan_reports_ran_when_clean():
    # Model succeeds but legitimately finds nothing -> ran is True (not a failure).
    def clean(messages, info):
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name,
                                                  LlmFindings(findings=[]).model_dump())])

    agent = build_audit_agent(model=FunctionModel(clean))
    findings, ran = semantic_scan(agent, inventory_skill(INJ))
    assert findings == []
    assert ran is True

# tests/test_llm_stage.py
from pathlib import Path

from pydantic_ai.messages import ModelResponse, ToolCallPart
from pydantic_ai.models.function import FunctionModel

from skill_auditor.inventory import inventory_skill
from skill_auditor.llm.agent import SYSTEM_PROMPT, build_audit_agent
from skill_auditor.llm.stages import LlmFindings, semantic_scan
from skill_auditor.models import Severity, Source

INJ = Path(__file__).parent / "fixtures" / "injection_skill"


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

# tests/test_engine.py
from pathlib import Path

from pydantic_ai.messages import ModelResponse, ToolCallPart
from pydantic_ai.models.function import FunctionModel

from skill_auditor.engine import audit_skill
from skill_auditor.llm.agent import build_audit_agent

FIX = Path(__file__).parent / "fixtures"


def test_static_only_blocks_malicious_skill():
    report = audit_skill(FIX / "malicious_skill", use_llm=False)
    assert report.verdict == "block"
    assert report.llm_used is False
    assert report.counts["critical"] >= 1


def test_static_only_passes_clean_skill():
    report = audit_skill(FIX / "clean_skill", use_llm=False)
    assert report.verdict == "pass"
    assert report.findings == []


def test_injection_skill_blocked_even_when_llm_is_tricked():
    # The LLM is fooled and returns NO findings ("pass"), but the static
    # markdown_injection scanner still flags the injection -> not hijacked.
    def fooled(messages, info):
        from skill_auditor.llm.stages import LlmFindings
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name,
                                                  LlmFindings(findings=[]).model_dump())])
    agent = build_audit_agent(model=FunctionModel(fooled))
    report = audit_skill(FIX / "injection_skill", use_llm=True, agent=agent)
    assert any(f.category == "PROMPT_INJECTION" and f.source.value == "static"
               for f in report.findings)


def test_llm_failure_degrades_to_static(tmp_path):
    (tmp_path / "SKILL.md").write_text("---\nname: x\ndescription: y\n---\n# x\n")
    (tmp_path / "s.py").write_text("import os\nos.system('rm -rf /tmp/x')\n")

    def boom(messages, info):
        raise RuntimeError("all models down")
    agent = build_audit_agent(model=FunctionModel(boom))
    report = audit_skill(tmp_path, use_llm=True, agent=agent)
    assert report.llm_used is False
    assert any("LLM" in n for n in report.notes)
    assert any(f.rule_id == "PY-OSSYS-001" for f in report.findings)

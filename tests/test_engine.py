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


def test_oversized_payload_is_not_a_silent_pass(tmp_path):
    # A malicious script padded past the size limit is never read by the AST
    # scanner. Without coverage reporting this would PASS silently — the gap
    # must instead surface as a finding.
    (tmp_path / "SKILL.md").write_text("---\nname: x\ndescription: y\n---\n# x\n")
    (tmp_path / "evil.py").write_text("eval('payload')\n" + "# " + "x" * 1_000_001)
    report = audit_skill(tmp_path, use_llm=False)
    assert any(f.rule_id == "AUDIT-COVERAGE-001" and f.file == "evil.py"
               for f in report.findings)


def test_disguised_python_payload_is_caught(tmp_path):
    # A malicious script renamed to .txt must still be statically analyzed.
    (tmp_path / "SKILL.md").write_text("---\nname: x\ndescription: y\n---\n# x\n")
    (tmp_path / "payload.txt").write_text("import os\nos.system('rm -rf /tmp/x')\n")
    report = audit_skill(tmp_path, use_llm=False)
    assert any(f.rule_id == "PY-OSSYS-001" and f.file == "payload.txt"
               for f in report.findings)


def test_llm_truncation_is_noted(tmp_path):
    from skill_auditor.llm.stages import MAX_FILE_CHARS, LlmFindings
    (tmp_path / "SKILL.md").write_text("---\nname: x\ndescription: y\n---\n# x\n")
    (tmp_path / "big.md").write_text("a" * (MAX_FILE_CHARS + 10))

    def clean(messages, info):
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name,
                                                 LlmFindings(findings=[]).model_dump())])
    agent = build_audit_agent(model=FunctionModel(clean))
    report = audit_skill(tmp_path, use_llm=True, agent=agent)
    assert any("truncated" in n.lower() and "big.md" in n for n in report.notes)


def test_clean_skill_with_working_llm_marks_llm_used(tmp_path):
    # LLM ran and found nothing -> llm_used True (distinct from "LLM unavailable").
    (tmp_path / "SKILL.md").write_text("---\nname: x\ndescription: y\n---\n# x\n")

    def clean(messages, info):
        from skill_auditor.llm.stages import LlmFindings
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name,
                                                 LlmFindings(findings=[]).model_dump())])
    agent = build_audit_agent(model=FunctionModel(clean))
    report = audit_skill(tmp_path, use_llm=True, agent=agent)
    assert report.llm_used is True
    assert not any("unavailable" in n.lower() for n in report.notes)


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

# src/skill_auditor/llm/stages.py
"""LLM stages: semantic_scan (new findings) and adjudicate (triage static ones)."""

from __future__ import annotations

from pydantic import BaseModel

from skill_auditor.inventory import SkillFile
from skill_auditor.models import Finding, Severity, Source

MAX_FILE_CHARS = 6000


class LlmFindings(BaseModel):
    findings: list[dict]


def _render_untrusted(files: list[SkillFile]) -> str:
    blocks = []
    for f in files:
        if f.text is None or f.kind == "asset":
            continue
        body = f.text[:MAX_FILE_CHARS]
        blocks.append(f"<skill_file path=\"{f.relpath}\" kind=\"{f.kind}\">\n{body}\n</skill_file>")
    return "\n".join(blocks)


def _coerce(raw: dict) -> Finding | None:
    try:
        return Finding(
            rule_id=str(raw.get("rule_id") or "LLM-001"),
            category=str(raw.get("category") or "PROMPT_INJECTION"),
            severity=Severity(str(raw.get("severity", "medium")).lower()),
            title=str(raw.get("title") or "LLM finding"),
            file=str(raw.get("file") or "SKILL.md"),
            line=raw.get("line"),
            evidence=str(raw.get("evidence") or "")[:200],
            explanation=str(raw.get("explanation") or ""),
            remediation=str(raw.get("remediation") or ""),
            source=Source.LLM,
            confidence=float(raw.get("confidence", 0.6)),
        )
    except (ValueError, TypeError):
        return None


def semantic_scan(agent, files: list[SkillFile]) -> tuple[list[Finding], bool]:
    """Ask the LLM for injection/intent findings.

    Returns (findings, ran). `ran` is True when the model responded (even with
    zero findings) and False on any model failure, so the caller can tell
    "LLM examined this and it's clean" from "LLM never ran".
    """
    prompt = ("Analyze these skill files for prompt injection and intent mismatch.\n\n"
              + _render_untrusted(files))
    try:
        result = agent.run_sync(prompt, output_type=LlmFindings)
    except Exception:  # noqa: BLE001 — rate limits / network / all models down -> degrade
        return [], False
    findings = [c for c in (_coerce(r) for r in result.output.findings) if c is not None]
    return findings, True

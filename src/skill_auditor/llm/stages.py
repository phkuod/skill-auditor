# src/skill_auditor/llm/stages.py
"""LLM stages: semantic_scan (new findings) and adjudicate (triage static ones)."""

from __future__ import annotations

from pydantic import BaseModel

from skill_auditor.inventory import SkillFile
from skill_auditor.models import Finding, Severity, Source

MAX_FILE_CHARS = 6000
LLM_TIMEOUT_SECONDS = 30.0  # cap a hung free-tier model so degradation actually triggers


class LlmFindings(BaseModel):
    findings: list[dict]


class _Adjudication(BaseModel):
    items: list[dict]  # [{index:int, confidence:float, note:str}]


def truncated_for_llm(files: list[SkillFile]) -> list[str]:
    """Relpaths of scannable files whose text is longer than the LLM sees.

    Content past MAX_FILE_CHARS is cut from the prompt; the caller surfaces this
    so a payload hidden past the cutoff is not silently un-reviewed by the LLM.
    """
    return [f.relpath for f in files
            if f.text is not None and f.kind != "asset" and len(f.text) > MAX_FILE_CHARS]


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
        result = agent.run_sync(prompt, output_type=LlmFindings,
                                model_settings={"timeout": LLM_TIMEOUT_SECONDS})
    except Exception:  # noqa: BLE001 — rate limits / network / timeout / all down -> degrade
        return [], False
    findings = [c for c in (_coerce(r) for r in result.output.findings) if c is not None]
    return findings, True


def adjudicate(agent, findings: list[Finding], files: list[SkillFile]) -> tuple[list[Finding], bool]:
    """Re-rate each finding's confidence using the files as context (ADVISORY ONLY).

    Returns (findings, ran). The LLM can only adjust the `confidence` float — it
    cannot remove or downgrade a finding's severity, so a tricked model can never
    change the verdict (verdict is computed from severity in report.py). Returns
    the input unchanged with ran=False when there is nothing to do or on failure.
    """
    if not findings:
        return findings, False
    listing = "\n".join(
        f"[{i}] {f.rule_id} {f.severity.value} {f.file}:{f.line} — {f.title}"
        for i, f in enumerate(findings))
    prompt = ("Re-rate the confidence (0..1) that each finding below is a real risk, using the "
              "skill files as context. Return items {index, confidence, note}. Confidence is "
              "advisory only — you cannot remove or downgrade findings.\n\n"
              f"FINDINGS:\n{listing}\n\n" + _render_untrusted(files))
    try:
        result = agent.run_sync(prompt, output_type=_Adjudication,
                                model_settings={"timeout": LLM_TIMEOUT_SECONDS})
    except Exception:  # noqa: BLE001 — any model failure degrades to the static confidences
        return findings, False
    by_index: dict[int, float] = {}
    for item in result.output.items:
        if not isinstance(item, dict):
            continue
        try:
            idx, conf = int(item.get("index")), float(item.get("confidence"))
        except (TypeError, ValueError):
            continue
        if 0.0 <= conf <= 1.0 and 0 <= idx < len(findings):
            by_index[idx] = conf
    out = [f.model_copy(update={"confidence": by_index[i]}) if i in by_index else f
           for i, f in enumerate(findings)]
    return out, True

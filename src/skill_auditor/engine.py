# src/skill_auditor/engine.py
"""Orchestrate: inventory -> static scanners -> optional LLM stage -> report."""

from __future__ import annotations

from pathlib import Path

from skill_auditor.inventory import inventory_skill
from skill_auditor.llm.agent import build_audit_agent, build_model
from skill_auditor.llm.stages import adjudicate, semantic_scan, truncated_for_llm
from skill_auditor.models import AuditReport
from skill_auditor.report import build_report
from skill_auditor.scanners import run_all


def audit_skill(path: Path | str, *, use_llm: bool = True, agent=None) -> AuditReport:
    """Audit a skill directory. Never executes any of the skill's code."""
    skill_dir = Path(path).resolve()
    name = skill_dir.name
    files = inventory_skill(skill_dir)

    findings = run_all(files)            # deterministic backbone — always runs
    notes: list[str] = []
    llm_used = False

    if use_llm:
        if agent is None:
            model = build_model()
            agent = build_audit_agent(model) if model is not None else None
        if agent is None:
            notes.append("LLM skipped: no OPENROUTER_API_KEY set (static-only).")
        else:
            llm_findings, llm_ran = semantic_scan(agent, files)
            if llm_ran:
                findings.extend(llm_findings)
                llm_used = True
                truncated = truncated_for_llm(files)
                if truncated:
                    notes.append("LLM saw truncated content for "
                                 f"{len(truncated)} file(s) ({', '.join(truncated)}); "
                                 "review them manually.")
                # Advisory confidence re-rating; never changes severity or verdict.
                adjudicated, adj_ran = adjudicate(agent, findings, files)
                if adj_ran:
                    findings = adjudicated
            else:
                notes.append("LLM unavailable (all models failed); static-only backbone used.")

    return build_report(name, str(skill_dir), findings, llm_used=llm_used, notes=notes)

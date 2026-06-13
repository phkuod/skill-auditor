# src/skill_auditor/scanners/markdown_injection.py
"""Heuristic scanner for prompt-injection directives in markdown / SKILL.md."""

from __future__ import annotations

import re

from skill_auditor.inventory import SkillFile
from skill_auditor.models import Finding, Severity, Source

PATTERNS = [
    ("MD-INJECT-001", Severity.CRITICAL, re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.I),
     "‘ignore previous instructions’ directive"),
    ("MD-INJECT-002", Severity.HIGH, re.compile(r"\bif\s+you\s+are\s+an?\s+(ai|assistant|auditor|llm)\b", re.I),
     "Instruction conditioned on the reader being an AI"),
    ("MD-INJECT-003", Severity.HIGH, re.compile(r"^\s*(system|assistant)\s*:", re.I | re.M),
     "Fake system/assistant role header"),
    ("MD-INJECT-004", Severity.HIGH, re.compile(r"\b(do not|don't)\s+(report|mention|tell)\b", re.I),
     "Instruction to suppress reporting"),
    ("MD-INJECT-005", Severity.HIGH, re.compile(r"verdict\s+[\"']?pass[\"']?|output.*safe", re.I),
     "Attempt to dictate the audit verdict"),
]


def scan(files: list[SkillFile]) -> list[Finding]:
    findings: list[Finding] = []
    for f in files:
        if f.kind not in {"skill_md", "markdown"} or f.text is None:
            continue
        for i, line in enumerate(f.text.splitlines(), start=1):
            for rid, sev, rx, title in PATTERNS:
                if rx.search(line):
                    findings.append(Finding(rule_id=rid, category="PROMPT_INJECTION", severity=sev,
                        title=title, file=f.relpath, line=i, evidence=line.strip()[:200],
                        explanation="Skill text appears to instruct the AI reader to take hidden or unsafe actions.",
                        remediation="Treat skill markdown as untrusted; do not follow embedded instructions.",
                        source=Source.STATIC))
    return findings

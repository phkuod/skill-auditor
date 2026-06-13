# src/skill_auditor/scanners/shell.py
"""Regex scanner for shell scripts (and shell-looking lines in any text file)."""

from __future__ import annotations

import re

from skill_auditor.inventory import SkillFile
from skill_auditor.models import Finding, Severity, Source

# (rule_id, category, severity, compiled regex, title, explanation, remediation)
RULES = [
    ("SH-RMRF-001", "DESTRUCTIVE", Severity.CRITICAL,
     re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f|\brm\s+-[a-zA-Z]*f[a-zA-Z]*r"),
     "rm -rf recursive force delete", "Recursively force-deletes files.", "Remove or scope the rm command."),
    ("SH-CURLPIPE-001", "RCE_SUPPLY_CHAIN", Severity.CRITICAL,
     re.compile(r"\b(curl|wget)\b[^\n|]*\|\s*(sh|bash|zsh)\b"),
     "curl|bash remote code execution", "Downloads and executes a remote script.", "Never pipe network content into a shell."),
    ("SH-DD-001", "DESTRUCTIVE", Severity.HIGH, re.compile(r"\bdd\s+if=|\bmkfs\b"),
     "disk-destructive command", "dd/mkfs can destroy disks.", "Remove unless clearly justified."),
    ("SH-GITFORCE-001", "DESTRUCTIVE", Severity.MEDIUM, re.compile(r"git\s+push\b[^\n]*--force"),
     "git push --force", "Force-push can overwrite history.", "Avoid force-push in skill scripts."),
]


def scan(files: list[SkillFile]) -> list[Finding]:
    findings: list[Finding] = []
    for f in files:
        if f.kind not in {"shell", "skill_md", "markdown"} or f.text is None:
            continue
        for i, line in enumerate(f.text.splitlines(), start=1):
            for rid, cat, sev, rx, title, why, fix in RULES:
                if rx.search(line):
                    findings.append(Finding(rule_id=rid, category=cat, severity=sev, title=title,
                        file=f.relpath, line=i, evidence=line.strip()[:200],
                        explanation=why, remediation=fix, source=Source.STATIC))
    return findings

# src/skill_auditor/scanners/coverage.py
"""Coverage scanner: surfaces scannable files that could NOT be fully audited.

A security auditor that silently skips a file (oversized, unreadable) and still
returns 'pass' hides a real bypass — pad a malicious script past the size limit
and no other scanner ever sees it. This scanner makes those gaps visible.
"""

from __future__ import annotations

from skill_auditor.inventory import SkillFile
from skill_auditor.models import Finding, Severity, Source

CATEGORY = "AUDIT_COVERAGE"
RULE_ID = "AUDIT-COVERAGE-001"

_REASON_TEXT = {
    "too_large": "exceeds the size limit, so it was not read or statically analyzed",
    "unreadable": "could not be read, so it was not statically analyzed",
    "symlink": "is a symlink pointing outside the skill, so it was not followed or analyzed",
}


def scan(files: list[SkillFile]) -> list[Finding]:
    findings: list[Finding] = []
    for f in files:
        if f.skip_reason is None:
            continue
        why = _REASON_TEXT.get(f.skip_reason, "was not statically analyzed")
        findings.append(Finding(
            rule_id=RULE_ID, category=CATEGORY, severity=Severity.MEDIUM,
            title="File not statically analyzed", file=f.relpath, line=None,
            evidence=f"skip_reason={f.skip_reason}",
            explanation=f"This file {why}; a payload here would evade the static scanners.",
            remediation="Review the file manually, or split/shrink it so it can be scanned.",
            source=Source.STATIC))
    return findings

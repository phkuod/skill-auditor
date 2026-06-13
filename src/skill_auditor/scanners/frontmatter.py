# src/skill_auditor/scanners/frontmatter.py
"""Scanner for SKILL.md YAML frontmatter: over-permissioning and auto-run hooks."""

from __future__ import annotations

import yaml

from skill_auditor.inventory import SkillFile
from skill_auditor.models import Finding, Severity, Source


def _parse_frontmatter(text: str) -> dict | None:
    if not text.startswith("---"):
        return None
    parts = text.split("---", 2)
    if len(parts) < 3:
        return None
    try:
        data = yaml.safe_load(parts[1])
    except yaml.YAMLError:
        return None
    return data if isinstance(data, dict) else None


def scan(files: list[SkillFile]) -> list[Finding]:
    findings: list[Finding] = []
    for f in files:
        if f.kind != "skill_md" or f.text is None:
            continue
        meta = _parse_frontmatter(f.text)
        if meta is None:
            continue
        tools = meta.get("allowed-tools")
        if tools in ("*", ["*"]) or (isinstance(tools, list) and "*" in tools):
            findings.append(Finding(rule_id="FM-WILDCARD-001", category="OVER_PERMISSION",
                severity=Severity.HIGH, title="Wildcard allowed-tools", file=f.relpath, line=None,
                evidence=f"allowed-tools: {tools}", explanation="Grants the skill every tool, far more than it needs.",
                remediation="Restrict allowed-tools to the minimum set required.", source=Source.STATIC))
        if "hooks" in meta and meta["hooks"]:
            findings.append(Finding(rule_id="FM-HOOK-001", category="OVER_PERMISSION",
                severity=Severity.HIGH, title="Skill declares hooks", file=f.relpath, line=None,
                evidence=f"hooks: {meta['hooks']}", explanation="Hooks auto-run commands on tool events — high risk.",
                remediation="Review each hook command; remove unless essential.", source=Source.STATIC))
    return findings

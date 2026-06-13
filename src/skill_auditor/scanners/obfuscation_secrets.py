# src/skill_auditor/scanners/obfuscation_secrets.py
"""Scanner for obfuscation (base64/zero-width/homoglyph) and hardcoded secrets."""

from __future__ import annotations

import re

from skill_auditor.inventory import SkillFile
from skill_auditor.models import Finding, Severity, Source

# Zero-width space (U+200B), zero-width non-joiner (U+200C), zero-width joiner (U+200D),
# word joiner (U+2060), and byte-order mark / zero-width no-break space (U+FEFF).
ZERO_WIDTH = re.compile("[\u200b\u200c\u200d\u2060\ufeff]")
B64_EXEC = re.compile(r"(b64decode|b16decode|unhexlify|decode\([\"']hex)", re.I)
SECRET_RULES = [
    ("OB-SECRET-AWS-001", re.compile(r"AKIA[0-9A-Z]{16}"), "Hardcoded AWS access key id"),
    ("OB-SECRET-GH-001", re.compile(r"ghp_[A-Za-z0-9]{36}"), "Hardcoded GitHub token"),
    ("OB-SECRET-OR-001", re.compile(r"sk-or-v1-[A-Za-z0-9]{16,}"), "Hardcoded OpenRouter key"),
    ("OB-SECRET-GENERIC-001",
     re.compile(r"(?i)(password|passwd|secret|api[_-]?key)\s*[=:]\s*[\"'][^\"']{6,}[\"']"),
     "Hardcoded credential literal"),
]


def scan(files: list[SkillFile]) -> list[Finding]:
    findings: list[Finding] = []
    for f in files:
        if f.text is None:
            continue
        lines = f.text.splitlines()
        for i, line in enumerate(lines, start=1):
            if ZERO_WIDTH.search(line):
                findings.append(Finding(rule_id="OB-ZEROWIDTH-001", category="OBFUSCATION",
                    severity=Severity.HIGH, title="Zero-width / invisible characters", file=f.relpath, line=i,
                    evidence=repr(line[:120]), explanation="Invisible characters can hide instructions or code.",
                    remediation="Strip invisible characters and re-inspect.", source=Source.STATIC))
            if f.kind == "python" and B64_EXEC.search(line):
                findings.append(Finding(rule_id="OB-B64EXEC-001", category="OBFUSCATION",
                    severity=Severity.HIGH, title="Encoded payload decode", file=f.relpath, line=i,
                    evidence=line.strip()[:200], explanation="Decoding then executing data hides intent.",
                    remediation="Inspect the decoded payload; avoid runtime decode-execute.", source=Source.STATIC))
            for rid, rx, title in SECRET_RULES:
                if rx.search(line):
                    findings.append(Finding(rule_id=rid, category="SECRETS", severity=Severity.HIGH,
                        title=title, file=f.relpath, line=i, evidence=line.strip()[:120],
                        explanation="A hardcoded secret should never ship in a skill.",
                        remediation="Remove the secret and rotate it.", source=Source.STATIC))
    return findings

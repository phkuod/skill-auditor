# src/skill_auditor/scanners/__init__.py
"""Static scanners. Each module exposes scan(files) -> list[Finding]."""

from __future__ import annotations

from skill_auditor.inventory import SkillFile
from skill_auditor.models import Finding
from skill_auditor.scanners import (
    coverage,
    filesystem,
    frontmatter,
    markdown_injection,
    obfuscation_secrets,
    python_ast,
    shell,
)

SCANNERS = [python_ast, shell, markdown_injection, frontmatter, obfuscation_secrets,
            filesystem, coverage]


def run_all(files: list[SkillFile]) -> list[Finding]:
    findings: list[Finding] = []
    for scanner in SCANNERS:
        findings.extend(scanner.scan(files))
    return findings


def _build_rules_catalog() -> dict[str, dict]:
    """Static catalog of rule metadata for the GET /rules endpoint and docs."""
    catalog: dict[str, dict] = {}
    # python_ast
    for v in python_ast.DANGEROUS_CALLS.values():
        catalog[v[0]] = {"category": v[1], "severity": v[2].value, "description": v[3]}
    for v in python_ast.DANGEROUS_ATTR_CALLS.values():
        catalog[v[0]] = {"category": v[1], "severity": v[2].value, "description": v[3]}
    for v in python_ast.DANGEROUS_METHODS.values():
        catalog[v[0]] = {"category": v[1], "severity": v[2].value, "description": v[3]}
    catalog["PY-SECRET-READ-001"] = {"category": "EXFILTRATION", "severity": "high",
                                     "description": "Reference to a sensitive path"}
    catalog["PY-PARSE-001"] = {"category": "OBFUSCATION", "severity": "medium",
                               "description": "Python file does not parse"}
    # shell
    for rid, cat, sev, _rx, title, *_ in shell.RULES:
        catalog[rid] = {"category": cat, "severity": sev.value, "description": title}
    # markdown injection
    for rid, sev, _rx, title in markdown_injection.PATTERNS:
        catalog[rid] = {"category": "PROMPT_INJECTION", "severity": sev.value, "description": title}
    # frontmatter
    catalog["FM-WILDCARD-001"] = {"category": "OVER_PERMISSION", "severity": "high",
                                  "description": "Wildcard allowed-tools"}
    catalog["FM-HOOK-001"] = {"category": "OVER_PERMISSION", "severity": "high",
                              "description": "Skill declares hooks"}
    # obfuscation + secrets
    catalog["OB-ZEROWIDTH-001"] = {"category": "OBFUSCATION", "severity": "high",
                                   "description": "Zero-width / invisible characters"}
    catalog["OB-B64EXEC-001"] = {"category": "OBFUSCATION", "severity": "high",
                                 "description": "Encoded payload decode (base64/hex/rot13)"}
    catalog["OB-HOMOGLYPH-001"] = {"category": "OBFUSCATION", "severity": "high",
                                   "description": "Mixed-script homoglyph (Latin + Cyrillic/Greek)"}
    catalog["OB-LONGLINE-001"] = {"category": "OBFUSCATION", "severity": "medium",
                                  "description": "Abnormally long line (possible encoded blob)"}
    for rid, _rx, title in obfuscation_secrets.SECRET_RULES:
        catalog[rid] = {"category": "SECRETS", "severity": "high", "description": title}
    # filesystem
    catalog["FS-TRAVERSAL-001"] = {"category": filesystem.CATEGORY, "severity": "medium",
                                   "description": "Path traversal ('../') sequence"}
    catalog["FS-ABSWRITE-001"] = {"category": filesystem.CATEGORY, "severity": "high",
                                  "description": "Write to an absolute path outside the skill"}
    # coverage
    catalog[coverage.RULE_ID] = {"category": coverage.CATEGORY, "severity": "medium",
                                 "description": "File could not be fully audited (skipped/too large)"}
    return catalog


RULES: dict[str, dict] = _build_rules_catalog()

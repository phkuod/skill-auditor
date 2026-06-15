# src/skill_auditor/scanners/filesystem.py
"""FILESYSTEM scanner: path traversal and writes outside the skill directory.

Covers the spec's FILESYSTEM category: a skill should read/write within its own
tree, not escape via `../` or write to absolute system paths.
"""

from __future__ import annotations

import ast
import re

from skill_auditor.inventory import SkillFile
from skill_auditor.models import Finding, Severity, Source

CATEGORY = "FILESYSTEM"
_TRAVERSAL_RE = re.compile(r"\.\.[\\/]")
_WRITE_MODES = ("w", "a", "x", "+")


def _is_absolute(path: str) -> bool:
    return path.startswith(("/", "~", "\\")) or bool(re.match(r"^[A-Za-z]:[\\/]", path))


def _traversal(rule_file: str, line: int | None, evidence: str) -> Finding:
    return Finding(rule_id="FS-TRAVERSAL-001", category=CATEGORY, severity=Severity.MEDIUM,
        title="Path traversal sequence", file=rule_file, line=line, evidence=evidence[:200],
        explanation="A '../' path can read or write outside the skill's own directory.",
        remediation="Use paths relative to the skill root; reject '..' segments.",
        source=Source.STATIC)


def _scan_python(f: SkillFile) -> list[Finding]:
    try:
        tree = ast.parse(f.text)
    except (SyntaxError, ValueError):
        return []  # python_ast already reports unparseable files
    lines = f.text.splitlines()
    out: list[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and _TRAVERSAL_RE.search(node.value):
            ln = getattr(node, "lineno", None)
            ev = lines[ln - 1].strip() if ln and ln <= len(lines) else node.value
            out.append(_traversal(f.relpath, ln, ev))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
            args = node.args
            if len(args) >= 2 and isinstance(args[0], ast.Constant) and isinstance(args[0].value, str) \
                    and isinstance(args[1], ast.Constant) and isinstance(args[1].value, str):
                path, mode = args[0].value, args[1].value
                if _is_absolute(path) and any(m in mode for m in _WRITE_MODES):
                    out.append(Finding(rule_id="FS-ABSWRITE-001", category=CATEGORY, severity=Severity.HIGH,
                        title="Write to an absolute path", file=f.relpath, line=node.lineno,
                        evidence=f"open({path!r}, {mode!r})",
                        explanation="Writing to an absolute path lets the skill modify files outside its directory.",
                        remediation="Write only within the skill's own working directory.",
                        source=Source.STATIC))
    return out


def scan(files: list[SkillFile]) -> list[Finding]:
    findings: list[Finding] = []
    for f in files:
        if f.text is None:
            continue
        if f.kind == "python":
            findings.extend(_scan_python(f))
        elif f.kind in ("shell", "config"):
            for i, line in enumerate(f.text.splitlines(), start=1):
                if _TRAVERSAL_RE.search(line):
                    findings.append(_traversal(f.relpath, i, line.strip()))
    return findings

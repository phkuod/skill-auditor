# src/skill_auditor/scanners/python_ast.py
"""AST-based scanner for Python files: code execution, network, secret access."""

from __future__ import annotations

import ast

from skill_auditor.inventory import SkillFile
from skill_auditor.models import Finding, Severity, Source

DANGEROUS_CALLS = {
    "eval": ("PY-EXEC-001", "RCE_SUPPLY_CHAIN", Severity.CRITICAL, "eval() executes arbitrary code"),
    "exec": ("PY-EXEC-002", "RCE_SUPPLY_CHAIN", Severity.CRITICAL, "exec() executes arbitrary code"),
    "compile": ("PY-EXEC-003", "RCE_SUPPLY_CHAIN", Severity.HIGH, "compile() builds executable code"),
    "__import__": ("PY-IMPORT-001", "RCE_SUPPLY_CHAIN", Severity.HIGH, "dynamic __import__()"),
}
# dotted calls: module.attr
DANGEROUS_ATTR_CALLS = {
    ("subprocess", "run"): ("PY-SUBPROC-001", "RCE_SUPPLY_CHAIN", Severity.HIGH, "subprocess execution"),
    ("subprocess", "Popen"): ("PY-SUBPROC-002", "RCE_SUPPLY_CHAIN", Severity.HIGH, "subprocess execution"),
    ("os", "system"): ("PY-OSSYS-001", "RCE_SUPPLY_CHAIN", Severity.HIGH, "os.system shell execution"),
    ("pickle", "loads"): ("PY-PICKLE-001", "RCE_SUPPLY_CHAIN", Severity.HIGH, "pickle.loads is unsafe"),
    ("shutil", "rmtree"): ("PY-RMTREE-001", "DESTRUCTIVE", Severity.HIGH, "recursive delete"),
    ("requests", "post"): ("PY-NET-001", "EXFILTRATION", Severity.HIGH, "outbound network POST"),
    ("requests", "get"): ("PY-NET-002", "EXFILTRATION", Severity.MEDIUM, "outbound network GET"),
    ("urllib", "urlopen"): ("PY-NET-003", "EXFILTRATION", Severity.MEDIUM, "outbound network request"),
}
SECRET_PATH_HINTS = (".ssh", "id_rsa", ".env", ".aws", "credentials", ".netrc")


def _attr_chain(node: ast.AST) -> tuple[str, str] | None:
    """For `a.b(...)` return ('a','b'); else None."""
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return (node.value.id, node.attr)
    return None


def _scan_source(relpath: str, source: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return [Finding(
            rule_id="PY-PARSE-001", category="OBFUSCATION", severity=Severity.MEDIUM,
            title="Python file does not parse", file=relpath, line=None,
            evidence="<unparseable>", explanation="A skill script that cannot be parsed cannot be reviewed and may be obfuscated.",
            remediation="Manually inspect this file before trusting the skill.", source=Source.STATIC,
        )]
    lines = source.splitlines()

    def ev(node) -> str:
        i = getattr(node, "lineno", 0)
        return lines[i - 1].strip()[:200] if 1 <= i <= len(lines) else ""

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in DANGEROUS_CALLS:
                rid, cat, sev, why = DANGEROUS_CALLS[func.id]
                findings.append(Finding(rule_id=rid, category=cat, severity=sev,
                    title=f"{func.id}() call", file=relpath, line=node.lineno, evidence=ev(node),
                    explanation=why, remediation=f"Remove or justify the {func.id}() call.", source=Source.STATIC))
            chain = _attr_chain(func)
            if chain and chain in DANGEROUS_ATTR_CALLS:
                rid, cat, sev, why = DANGEROUS_ATTR_CALLS[chain]
                findings.append(Finding(rule_id=rid, category=cat, severity=sev,
                    title=f"{chain[0]}.{chain[1]}() call", file=relpath, line=node.lineno, evidence=ev(node),
                    explanation=why, remediation="Verify this call is necessary and safe.", source=Source.STATIC))
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            low = node.value.lower()
            if any(h in low for h in SECRET_PATH_HINTS):
                findings.append(Finding(rule_id="PY-SECRET-READ-001", category="EXFILTRATION",
                    severity=Severity.HIGH, title="Reference to a sensitive path", file=relpath,
                    line=getattr(node, "lineno", None), evidence=ev(node),
                    explanation=f"References a sensitive location ({node.value!r}); may read credentials.",
                    remediation="Confirm the skill has no reason to touch credential files.", source=Source.STATIC))
    return findings


def scan(files: list[SkillFile]) -> list[Finding]:
    findings: list[Finding] = []
    for f in files:
        if f.kind == "python" and f.text is not None:
            findings.extend(_scan_source(f.relpath, f.text))
    return findings

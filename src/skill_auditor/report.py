# src/skill_auditor/report.py
"""Verdict logic, severity counts, exit codes, and rich rendering."""

from __future__ import annotations

from rich.console import Console

from skill_auditor.models import AuditReport, Finding, Severity

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
SEVERITY_COLOR = {
    Severity.CRITICAL: "bold red", Severity.HIGH: "red", Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan", Severity.INFO: "dim",
}
VERDICT_COLOR = {"block": "bold red", "warn": "yellow", "pass": "green"}


def compute_verdict(findings: list[Finding]) -> str:
    sevs = {f.severity for f in findings}
    if Severity.CRITICAL in sevs:
        return "block"
    if Severity.HIGH in sevs:
        return "warn"
    return "pass"


def count_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts = {s.value: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity.value] += 1
    return counts


def build_report(skill_name: str, skill_path: str, findings: list[Finding], *,
                 llm_used: bool, notes: list[str]) -> AuditReport:
    return AuditReport(skill_name=skill_name, skill_path=skill_path,
        verdict=compute_verdict(findings),
        findings=sorted(findings, key=lambda f: SEVERITY_ORDER.index(f.severity)),
        counts=count_by_severity(findings), llm_used=llm_used, notes=notes)


def verdict_exit_code(verdict: str, fail_on: str = "critical") -> int:
    """Exit non-zero when verdict meets/exceeds the fail-on threshold."""
    rank = {"pass": 0, "warn": 1, "block": 2}
    threshold = {"critical": 2, "high": 1, "medium": 1}[fail_on]
    return rank[verdict] if rank[verdict] >= threshold else 0


def render_report(report: AuditReport, console: Console | None = None) -> None:
    console = console or Console()
    color = VERDICT_COLOR.get(report.verdict, "white")
    console.print(f"\n[bold]Skill:[/] {report.skill_name}  [dim]{report.skill_path}[/]")
    console.print(f"[{color}]VERDICT: {report.verdict.upper()}[/]  "
                  f"({', '.join(f'{k}={v}' for k, v in report.counts.items() if v)})")
    if not report.llm_used:
        console.print("[dim]· static-only (LLM not used)[/]")
    for note in report.notes:
        console.print(f"[dim]note: {note}[/]")
    for f in report.findings:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        sev = SEVERITY_COLOR.get(f.severity, "white")
        console.print(f"\n[{sev}]{f.severity.value.upper()}[/] [bold]{f.title}[/] "
                      f"[dim]{f.rule_id} · {f.category} · {f.source.value}[/]")
        console.print(f"  {loc}")
        if f.evidence:
            console.print(f"  [dim]{f.evidence}[/]")
        if f.explanation:
            console.print(f"  why: {f.explanation}")
        if f.remediation:
            console.print(f"  fix: {f.remediation}")
    console.print()

"""CLI adapter: skill-audit <path> [--no-llm] [--json] [--fail-on LEVEL] [--quiet]."""

from __future__ import annotations

import argparse
from pathlib import Path

from rich.console import Console

from skill_auditor.engine import audit_skill
from skill_auditor.report import render_report, verdict_exit_code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="skill-audit",
        description="Audit a downloaded Agent Skill for security problems (read-only).")
    parser.add_argument("path", type=Path, help="path to the skill directory")
    parser.add_argument("--no-llm", action="store_true", help="static scanners only")
    parser.add_argument("--json", action="store_true", help="emit AuditReport as JSON")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium"], default="critical")
    parser.add_argument("--quiet", action="store_true", help="suppress rich output")
    args = parser.parse_args(argv)

    skill_dir = args.path.resolve()
    if not skill_dir.is_dir():
        parser.error(f"skill directory does not exist: {skill_dir}")

    report = audit_skill(skill_dir, use_llm=not args.no_llm)

    if args.json:
        print(report.model_dump_json(indent=2))
    elif not args.quiet:
        render_report(report, Console())

    return verdict_exit_code(report.verdict, fail_on=args.fail_on)

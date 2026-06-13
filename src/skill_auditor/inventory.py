# src/skill_auditor/inventory.py
"""Walk a skill directory and classify each file (read-only, never executes)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

EXCLUDED_DIRS = {".git", "__pycache__", ".venv", "node_modules", ".pytest_cache"}
TEXT_KINDS = {"skill_md", "python", "shell", "markdown", "config"}
MAX_TEXT_BYTES = 1_000_000


def classify(relpath: str) -> str:
    name = relpath.replace("\\", "/")
    base = name.rsplit("/", 1)[-1].lower()
    if base == "skill.md":
        return "skill_md"
    if base.endswith(".py"):
        return "python"
    if base.endswith((".sh", ".bash", ".zsh")):
        return "shell"
    if base.endswith((".md", ".markdown")):
        return "markdown"
    if base.endswith((".yaml", ".yml", ".json", ".toml", ".cfg", ".ini")):
        return "config"
    return "asset"


@dataclass(frozen=True)
class SkillFile:
    path: Path        # absolute
    relpath: str      # posix-style, relative to skill root
    kind: str
    text: str | None  # None for binary/asset or unreadable


def _read_text(path: Path, kind: str) -> str | None:
    if kind == "asset":
        return None
    try:
        if path.stat().st_size > MAX_TEXT_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def inventory_skill(skill_dir: Path) -> list[SkillFile]:
    root = skill_dir.resolve()
    out: list[SkillFile] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if any(part in EXCLUDED_DIRS for part in rel.parts):
            continue
        relpath = rel.as_posix()
        kind = classify(relpath)
        out.append(SkillFile(path=path, relpath=relpath, kind=kind, text=_read_text(path, kind)))
    return out

# src/skill_auditor/inventory.py
"""Walk a skill directory and classify each file (read-only, never executes)."""

from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass
from pathlib import Path

EXCLUDED_DIRS = {".git", "__pycache__", ".venv", "node_modules", ".pytest_cache"}
TEXT_KINDS = {"skill_md", "python", "shell", "markdown", "config"}
MAX_TEXT_BYTES = 1_000_000

_SHEBANG_PY = re.compile(r"^#!.*\bpython")
_SHEBANG_SH = re.compile(r"^#!.*\b(?:bash|sh|zsh)\b")


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
    skip_reason: str | None = None  # set when a scannable file could NOT be fully read


def _read_text(path: Path, kind: str) -> tuple[str | None, str | None]:
    """Return (text, skip_reason). skip_reason is set only for scannable files
    we failed to read fully — binary assets are intentional and not a gap."""
    if kind == "asset":
        return None, None
    try:
        if path.stat().st_size > MAX_TEXT_BYTES:
            return None, "too_large"
        return path.read_text(encoding="utf-8", errors="replace"), None
    except OSError:
        return None, "unreadable"


def _sniff_executable(path: Path) -> tuple[str | None, str | None]:
    """Detect code hiding behind a non-code extension (e.g. payload.py -> .txt).

    Returns (kind, text) when the bytes are real source — a python/shell shebang
    or text that parses as a Python module — else (None, None). Binary files fail
    strict UTF-8 decode and stay assets, so they are never misclassified.
    """
    try:
        if path.stat().st_size > MAX_TEXT_BYTES:
            return None, None
        raw = path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeDecodeError):
        return None, None
    first = raw.split("\n", 1)[0]
    if _SHEBANG_PY.match(first):
        return "python", raw
    if _SHEBANG_SH.match(first):
        return "shell", raw
    try:
        tree = ast.parse(raw)
    except (SyntaxError, ValueError):
        return None, None
    return ("python", raw) if tree.body else (None, None)


def _within_root(root: Path, candidate: Path) -> bool:
    """True if candidate is root itself or lives somewhere under root."""
    return candidate == root or root in candidate.parents


def inventory_skill(skill_dir: Path) -> list[SkillFile]:
    root = skill_dir.resolve()
    out: list[SkillFile] = []
    # followlinks=False: never descend a symlinked directory (could escape the tree or loop).
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            rel = path.relative_to(root)
            if any(part in EXCLUDED_DIRS for part in rel.parts):
                continue
            relpath = rel.as_posix()
            kind = classify(relpath)
            # A symlink pointing outside the skill would let us read e.g. ~/.ssh; do not follow it.
            if path.is_symlink() and not _within_root(root, path.resolve()):
                out.append(SkillFile(path=path, relpath=relpath, kind=kind, text=None, skip_reason="symlink"))
                continue
            text, skip_reason = _read_text(path, kind)
            if kind == "asset":
                sniffed_kind, sniffed_text = _sniff_executable(path)
                if sniffed_kind is not None:
                    kind, text = sniffed_kind, sniffed_text
            out.append(SkillFile(path=path, relpath=relpath, kind=kind, text=text, skip_reason=skip_reason))
    out.sort(key=lambda f: f.relpath)
    return out

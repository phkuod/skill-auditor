# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`skill-auditor` is a static-first, LLM-assisted security auditor for **untrusted Agent Skills** downloaded from the internet. It reads a skill directory (`SKILL.md` + scripts/assets), flags risky behaviour, and emits a severity-ranked `AuditReport`. The product is one pure function — `audit_skill(path, *, use_llm=True, agent=None) -> AuditReport` — and the CLI / Web API are thin adapters over it.

## Two safety invariants (do not break these)

These are the reason the project exists; every change must preserve them:

1. **Never execute audited code.** Skill content is only ever `read_text`'d, `ast.parse`'d, regex-matched, or passed to the LLM as *data*. There is no `subprocess`/`exec`/`import` of skill content, no sandbox, no dynamic execution. The API extracts uploaded zips and only scans them.
2. **The auditor itself must not be hijackable.** Untrusted skill text is fed to the LLM, so the LLM is a prompt-injection target. Mitigations: skill text is wrapped in `<skill_file>` tags and framed as untrusted data in `SYSTEM_PROMPT`; the LLM has no action tools (it can only emit `Finding[]`); and `scanners/markdown_injection.py` flags injection attempts statically, so even a fooled LLM cannot make the verdict `pass`. See `tests/test_engine.py::test_injection_skill_blocked_even_when_llm_is_tricked`.

## Architecture (the pipeline)

`engine.audit_skill()` orchestrates four stages; read these to understand data flow:

1. **`inventory.py`** — walks the skill dir read-only (`os.walk(followlinks=False)`), classifies each file by extension into a `kind` (`skill_md`/`python`/`shell`/`markdown`/`config`/`asset`), and reads text. Two non-obvious behaviours: it **content-sniffs `asset` files** (shebang / parses-as-Python) and reclassifies disguised code (e.g. `payload.py` renamed `.txt`); and it records `skip_reason` (`too_large`/`unreadable`/`symlink`) for scannable files it could not fully read or that escape the root via symlink.
2. **`scanners/` (deterministic backbone, always runs)** — `run_all(files)` calls every scanner. Each scanner module exposes the uniform interface `scan(files: list[SkillFile]) -> list[Finding]`. Static findings have `source=static`, `confidence=1.0`.
3. **`llm/` (optional value-add, degrades gracefully)** — `stages.semantic_scan(agent, files)` returns `(findings, ran)`. `ran=False` on any model failure/timeout (so the engine can distinguish "LLM ran and found nothing" from "LLM never ran"); files truncated past `MAX_FILE_CHARS` are noted. Uses PydanticAI `FallbackModel` over free OpenRouter models; **no API key ⇒ LLM is skipped, static report still produced.**
4. **`report.py`** — `dedupe_findings()` drops exact dups and LLM findings that restate a static one (static wins); `compute_verdict()`: any CRITICAL → `block`, else any HIGH → `warn`, else `pass`; renders via `rich` or `model_dump_json()`.

Everything flows through the Pydantic models in `models.py` (`Finding`, `AuditReport`, `Severity`, `Source`) — output is always structured, never free text.

Dependency direction: adapters (`cli.py`, `api.py`) → `engine` → {`inventory`, `scanners`, `llm`, `report`}; all → `models`. No cycles.

## Adding a scanner (the most common change)

Each risk category is one pluggable module. To add detection:

1. Create `scanners/<name>.py` exposing `scan(files) -> list[Finding]`, with rule constants (rule_ids, categories, severities) at module level.
2. Register it in `scanners/__init__.py`: add to the `SCANNERS` list (so `run_all` includes it) **and** to `_build_rules_catalog()` (so `GET /rules` lists every `rule_id`).
3. Add `tests/test_scanner_<name>.py`: trigger on a malicious case, stay silent on `clean_skill`, assert `file:line`/`rule_id`/`severity`.

`engine.py` and `report.py` need no changes. Python detection should prefer the AST (`scanners/python_ast.py` — `DANGEROUS_CALLS` / `DANGEROUS_ATTR_CALLS` / `DANGEROUS_METHODS` dicts) over regex; shell/markdown use rule/heuristic lists.

## Commands

Uses `uv`. Run everything through `uv run`.

```bash
uv sync                                   # install deps
uv run pytest -q                          # all tests
uv run pytest tests/test_engine.py -q     # one file
uv run pytest tests/test_engine.py::test_static_only_passes_clean_skill   # one test
uv run pytest -q --cov=skill_auditor --cov-report=term-missing            # with coverage

# CLI (or ./run.ps1 <args> on Windows)
uv run python -m skill_auditor <skill-dir> [--no-llm] [--json] [--fail-on critical|high|medium] [--quiet]

# Web API (or ./start.ps1 [-Port N] [-AllowedRoot <dir>] [-Reload])
uv run uvicorn skill_auditor.api:app
```

Tests use PydanticAI `FunctionModel` for the LLM stage — **they never make real network calls**. Fixtures live in `tests/fixtures/` (`clean_skill` must stay silent across all scanners; `malicious_skill` has one sample per category; `injection_skill` tries to fool the auditor). `pyproject.toml` sets `norecursedirs = ["fixtures"]` so fixture scripts are not collected as tests.

## Conventions specific to this repo

- **CLI exit codes are part of the contract**: `pass`=0, `warn`=1, `block`=2, adjustable with `--fail-on`. The `run.ps1` wrapper preserves them.
- **API path-mode is opt-in and confined**: `POST /audit` with a local path returns 403 unless `SKILL_AUDITOR_ALLOWED_ROOT` is set and the resolved path stays within it (prevents the unauthenticated API from reading arbitrary host files); zip upload always works. The API has no auth — localhost/internal only.
- **Silent coverage gaps are bugs**: if a file can't be fully analyzed, surface it (`AUDIT-COVERAGE-001`) rather than skipping quietly — a security tool that silently doesn't look is worse than one that errors.
- Design rationale and the full rule catalog live in `docs/ARCHITECTURE.md`; the approved spec is in `docs/superpowers/specs/`.

# skill-auditor

Static + LLM security auditor for downloaded Agent Skills. Reads a skill directory,
flags risky scripts, prompt injection, over-permissioning, obfuscation, and secrets,
and emits a severity-ranked report. **It never executes the audited skill's code.**

## Install
```bash
uv sync
cp .env.example .env   # optional: add OPENROUTER_API_KEY to enable the LLM stage
```

## CLI
```bash
uv run python -m skill_auditor <skill-dir>            # full audit
uv run python -m skill_auditor --no-llm <skill-dir>   # static only
uv run python -m skill_auditor --json <skill-dir>     # machine output
```
Exit codes: pass=0, warn=1, block=2 (tune with `--fail-on`).

## Web API (no auth — localhost/internal only)
```bash
uv run uvicorn skill_auditor.api:app
# POST /audit  {"path": "...", "use_llm": false}  OR  multipart zip upload
# GET  /rules  ·  GET /health
```

## How it works
Deterministic static scanners (regex + Python `ast`) form the backbone and always run.
An optional, injection-hardened LLM stage adds semantic findings and degrades gracefully
when free models are unavailable. See `docs/superpowers/specs/2026-06-13-skill-auditor-design.md`.

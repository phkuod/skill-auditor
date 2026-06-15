# src/skill_auditor/api.py
"""FastAPI adapter. Auth is optional (set SKILL_AUDITOR_API_TOKEN); otherwise
deploy on localhost/internal only."""

from __future__ import annotations

import io
import secrets
import tempfile
import zipfile
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from skill_auditor.config import ALLOWED_ROOT_ENV_VAR, load_allowed_root, load_api_token
from skill_auditor.engine import audit_skill
from skill_auditor.scanners import RULES

app = FastAPI(title="skill-auditor", version="0.1.0")

MAX_ZIP_BYTES = 20_000_000
MAX_ZIP_ENTRIES = 2000


class AuditPathRequest(BaseModel):
    path: str
    use_llm: bool = True


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/rules")
def rules() -> dict:
    return {"rules": RULES}


def _check_token(request: Request) -> None:
    """Require a bearer token on /audit when SKILL_AUDITOR_API_TOKEN is set; no-op otherwise."""
    token = load_api_token()
    if token is None:
        return
    auth = request.headers.get("authorization", "")
    presented = auth[7:] if auth[:7].lower() == "bearer " else ""
    if not (presented and secrets.compare_digest(presented, token)):
        raise HTTPException(status_code=401, detail="missing or invalid API token")


def _safe_extract(zf: zipfile.ZipFile, dest: Path) -> None:
    names = zf.namelist()
    if len(names) > MAX_ZIP_ENTRIES:
        raise HTTPException(status_code=400, detail="archive has too many entries")
    dest_resolved = dest.resolve()
    for name in names:
        target = (dest / name).resolve()
        if target != dest_resolved and dest_resolved not in target.parents:
            raise HTTPException(status_code=400, detail=f"unsafe path in archive: {name}")
    zf.extractall(dest)


@app.post("/audit")
async def audit(request: Request, use_llm: bool = True, _: None = Depends(_check_token)) -> dict:
    content_type = request.headers.get("content-type", "")

    if content_type.startswith("multipart/form-data"):
        form = await request.form()
        upload = form.get("file")
        if upload is None:
            raise HTTPException(status_code=400, detail="no file provided")
        raw = await upload.read()
        if len(raw) > MAX_ZIP_BYTES:
            raise HTTPException(status_code=400, detail="archive too large")
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            try:
                with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                    _safe_extract(zf, tmpdir)
            except zipfile.BadZipFile:
                raise HTTPException(status_code=400, detail="not a valid zip archive")
            roots = list(tmpdir.rglob("SKILL.md"))
            skill_root = roots[0].parent if roots else tmpdir
            report = await run_in_threadpool(audit_skill, skill_root, use_llm=use_llm)
            return report.model_dump()

    body = await request.json()
    payload = AuditPathRequest.model_validate(body)
    allowed_root = load_allowed_root()
    if allowed_root is None:
        raise HTTPException(status_code=403,
            detail=f"path audits are disabled; set {ALLOWED_ROOT_ENV_VAR} or upload a zip")
    skill_dir = Path(payload.path).resolve()
    if skill_dir != allowed_root and allowed_root not in skill_dir.parents:
        raise HTTPException(status_code=403,
            detail=f"path is outside the allowed root: {payload.path}")
    if not skill_dir.is_dir():
        raise HTTPException(status_code=404, detail=f"not a directory: {payload.path}")
    report = await run_in_threadpool(audit_skill, skill_dir, use_llm=payload.use_llm)
    return report.model_dump()

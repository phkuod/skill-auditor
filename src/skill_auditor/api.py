# src/skill_auditor/api.py
"""FastAPI adapter. v1 has no auth — deploy on localhost/internal only."""

from __future__ import annotations

import io
import tempfile
import zipfile
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

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
async def audit(request: Request, use_llm: bool = True) -> dict:
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
            return audit_skill(skill_root, use_llm=use_llm).model_dump()

    body = await request.json()
    payload = AuditPathRequest.model_validate(body)
    skill_dir = Path(payload.path)
    if not skill_dir.is_dir():
        raise HTTPException(status_code=404, detail=f"not a directory: {payload.path}")
    return audit_skill(skill_dir, use_llm=payload.use_llm).model_dump()

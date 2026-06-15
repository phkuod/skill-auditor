# tests/test_api.py
import io
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient

from skill_auditor.api import app

FIX = Path(__file__).parent / "fixtures"
client = TestClient(app)


def test_health():
    assert client.get("/health").json() == {"status": "ok"}


def test_rules_lists_known_ids():
    body = client.get("/rules").json()
    assert "PY-EXEC-001" in body["rules"]


def test_audit_local_path_blocks_malicious(monkeypatch):
    monkeypatch.setenv("SKILL_AUDITOR_ALLOWED_ROOT", str(FIX))
    r = client.post("/audit", json={"path": str(FIX / "malicious_skill"), "use_llm": False})
    assert r.status_code == 200
    assert r.json()["verdict"] == "block"


def test_path_outside_allowed_root_is_forbidden(monkeypatch, tmp_path):
    monkeypatch.setenv("SKILL_AUDITOR_ALLOWED_ROOT", str(FIX))
    r = client.post("/audit", json={"path": str(tmp_path), "use_llm": False})
    assert r.status_code == 403


def test_path_mode_disabled_without_allowed_root(monkeypatch):
    monkeypatch.delenv("SKILL_AUDITOR_ALLOWED_ROOT", raising=False)
    r = client.post("/audit", json={"path": str(FIX / "malicious_skill"), "use_llm": False})
    assert r.status_code == 403


def _zip_of(dir_path: Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for p in dir_path.rglob("*"):
            if p.is_file():
                z.write(p, p.relative_to(dir_path).as_posix())
    return buf.getvalue()


def test_audit_zip_upload_passes_clean():
    data = _zip_of(FIX / "clean_skill")
    r = client.post("/audit?use_llm=false",
                    files={"file": ("clean.zip", data, "application/zip")})
    assert r.status_code == 200
    assert r.json()["verdict"] == "pass"


def test_zip_slip_is_rejected():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../escape.py", "import os")
    r = client.post("/audit?use_llm=false",
                    files={"file": ("evil.zip", buf.getvalue(), "application/zip")})
    assert r.status_code == 400
    assert "unsafe" in r.json()["detail"].lower()


def test_audit_requires_token_when_configured(monkeypatch):
    monkeypatch.setenv("SKILL_AUDITOR_API_TOKEN", "s3cret")
    data = _zip_of(FIX / "clean_skill")
    r = client.post("/audit?use_llm=false", files={"file": ("c.zip", data, "application/zip")})
    assert r.status_code == 401


def test_audit_accepts_correct_token(monkeypatch):
    monkeypatch.setenv("SKILL_AUDITOR_API_TOKEN", "s3cret")
    data = _zip_of(FIX / "clean_skill")
    r = client.post("/audit?use_llm=false", files={"file": ("c.zip", data, "application/zip")},
                    headers={"Authorization": "Bearer s3cret"})
    assert r.status_code == 200


def test_audit_open_when_token_unset(monkeypatch):
    monkeypatch.delenv("SKILL_AUDITOR_API_TOKEN", raising=False)
    data = _zip_of(FIX / "clean_skill")
    r = client.post("/audit?use_llm=false", files={"file": ("c.zip", data, "application/zip")})
    assert r.status_code == 200

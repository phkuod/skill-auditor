# tests/test_config.py
from skill_auditor.config import API_KEY_ENV_VAR, FREE_MODELS, load_api_key


def test_free_models_are_all_free_endpoints():
    assert len(FREE_MODELS) >= 2
    assert all(m.endswith(":free") for m in FREE_MODELS)


def test_load_api_key_returns_none_when_absent(monkeypatch, tmp_path):
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    assert load_api_key(env_file=tmp_path / "missing.env") is None


def test_load_api_key_reads_env(monkeypatch):
    monkeypatch.setenv(API_KEY_ENV_VAR, "sk-or-test")
    assert load_api_key() == "sk-or-test"

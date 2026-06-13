"""API key loading (optional) and the free-model fallback list."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

API_KEY_ENV_VAR = "OPENROUTER_API_KEY"

# Free OpenRouter endpoints that support tool calling, in fallback order.
FREE_MODELS: tuple[str, ...] = (
    "qwen/qwen3-coder:free",
    "openai/gpt-oss-120b:free",
    "meta-llama/llama-3.3-70b-instruct:free",
)


def load_api_key(env_file: Path | None = None) -> str | None:
    """Return the OpenRouter key from env/.env, or None if unset (static-only mode)."""
    load_dotenv(dotenv_path=env_file)
    key = os.environ.get(API_KEY_ENV_VAR, "").strip()
    return key or None

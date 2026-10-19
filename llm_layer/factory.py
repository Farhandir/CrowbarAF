"""Ortam degiskenlerinden LLM istemcisi uretir (model = config, bagimlilik degil)."""
from __future__ import annotations

import os

from .client import LLMClient


def from_env() -> LLMClient:
    provider = os.getenv("CROWBAR_LLM_PROVIDER", "ollama")
    model = os.getenv("CROWBAR_LLM_MODEL") or os.getenv("CROWBAR_OLLAMA_MODEL", "llama3.1")
    base_url = os.getenv("CROWBAR_LLM_BASE_URL") or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    api_key = os.getenv("CROWBAR_LLM_API_KEY")
    num_ctx = int(os.getenv("CROWBAR_LLM_NUM_CTX", "32768"))
    num_predict = int(os.getenv("CROWBAR_LLM_NUM_PREDICT", "1200"))
    return LLMClient(
        provider=provider,
        model=model,
        base_url=base_url,
        api_key=api_key,
        num_ctx=num_ctx,
        num_predict=num_predict,
    )

"""Local Ollama LLM factory. No data leaves the machine."""

from __future__ import annotations

import os

from langchain_ollama import ChatOllama

DEFAULT_MODEL = os.getenv("CROWBAR_OLLAMA_MODEL", "llama3.1")
DEFAULT_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")


def get_llm(model: str = DEFAULT_MODEL, temperature: float = 0.0) -> ChatOllama:
    return ChatOllama(model=model, base_url=DEFAULT_BASE_URL, temperature=temperature)

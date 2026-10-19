"""Model-agnostik LLM istemcisi: Ollama ve OpenAI-uyumlu sunucular (vLLM).

Dis bagimlilik yok (urllib). Boylece lokalde Ollama, kirali GPU'da vLLM,
istenirse API ayni kodla kullanilir.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass
class LLMResult:
    content: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    raw: dict | None = None


class LLMClient:
    def __init__(
        self,
        provider: str = "ollama",          # ollama | openai | vllm
        model: str = "qwen8:latest",
        base_url: str = "http://localhost:11434",
        api_key: str | None = None,
        num_ctx: int = 32768,
        num_predict: int = 1200,
        timeout: int = 1200,
    ) -> None:
        self.provider = provider
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.num_ctx = num_ctx
        self.num_predict = num_predict
        self.timeout = timeout

    # --- ortak ---
    def chat(self, messages: list[dict], json_mode: bool = True, temperature: float = 0.0) -> LLMResult:
        if self.provider == "ollama":
            return self._ollama(messages, json_mode, temperature)
        return self._openai(messages, json_mode, temperature)

    # --- Ollama /api/chat ---
    def _ollama(self, messages, json_mode, temperature) -> LLMResult:
        payload = {
            "model": self.model,
            "stream": False,
            "messages": messages,
            "think": False,
            "options": {
                "temperature": temperature,
                "num_ctx": self.num_ctx,
                "num_predict": self.num_predict,
            },
        }
        if json_mode:
            payload["format"] = "json"
        req = urllib.request.Request(
            self.base_url + "/api/chat",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            data = json.loads(r.read())
        return LLMResult(
            content=data.get("message", {}).get("content", ""),
            prompt_tokens=data.get("prompt_eval_count"),
            completion_tokens=data.get("eval_count"),
            raw=data,
        )

    # --- OpenAI-uyumlu /v1/chat/completions (vLLM, OpenAI, Anthropic proxy) ---
    def _openai(self, messages, json_mode, temperature) -> LLMResult:
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": self.num_predict,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(
            self.base_url + "/v1/chat/completions",
            data=json.dumps(payload).encode(),
            headers=headers,
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                data = json.loads(r.read())
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")[:500]
            raise RuntimeError(f"LLM HTTP {e.code}: {body}") from e
        usage = data.get("usage", {}) or {}
        return LLMResult(
            content=data["choices"][0]["message"]["content"],
            prompt_tokens=usage.get("prompt_tokens"),
            completion_tokens=usage.get("completion_tokens"),
            raw=data,
        )

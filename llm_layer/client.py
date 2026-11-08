"""Model-agnostic LLM client: Ollama and OpenAI-compatible servers (vLLM).

No external dependencies (urllib). This lets local Ollama, vLLM on a rented GPU,
and optionally an API all use the same code.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass


class LLMHTTPError(RuntimeError):
    """HTTP error with the status/body kept for the harness (context overflow etc.)."""

    def __init__(self, status: int, body: str) -> None:
        super().__init__(f"LLM HTTP {status}: {body[:500]}")
        self.status = status
        self.body = body


@dataclass
class LLMResult:
    content: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    raw: dict | None = None
    cost_usd: float | None = None
    billing_source: str | None = None
    allowance: float | None = None
    finish_reason: str | None = None


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
        user_agent: str = "crowbaraf/0.1",
        session_id: str | None = None,
        json_mode_supported: bool | None = None,
    ) -> None:
        self.provider = provider
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.num_ctx = num_ctx
        self.num_predict = num_predict
        self.timeout = timeout
        self.user_agent = user_agent
        self.session_id = session_id
        # None = unknown; True/False after the first attempt.
        self.json_mode_supported = json_mode_supported

    # --- shared ---
    def chat(self, messages: list[dict], json_mode: bool = True, temperature: float = 0.0,
             max_tokens: int | None = None) -> LLMResult:
        if self.provider == "ollama":
            return self._ollama(messages, json_mode, temperature, max_tokens)
        return self._openai(messages, json_mode, temperature, max_tokens)

    # --- Ollama /api/chat ---
    def _ollama(self, messages, json_mode, temperature, max_tokens=None) -> LLMResult:
        payload = {
            "model": self.model,
            "stream": False,
            "messages": messages,
            "think": False,
            "options": {
                "temperature": temperature,
                "num_ctx": self.num_ctx,
                "num_predict": max_tokens or self.num_predict,
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
            finish_reason=data.get("done_reason"),
        )

    def _openai_headers(self) -> dict:
        """Headers for OpenAI-compatible endpoints (incl. OpenCode Go)."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            # Go asks clients to identify themselves; generic SDK names are discouraged.
            "User-Agent": self.user_agent,
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        if self.session_id:
            headers["x-opencode-session"] = self.session_id
        return headers

    # --- OpenAI-uyumlu /v1/chat/completions (vLLM, OpenAI, OpenCode Go) ---
    def _json_attempts(self, json_mode: bool) -> list[bool]:
        """Try response_format, but fall back to prompt-only JSON on HTTP 400."""
        if not json_mode:
            return [False]
        if self.json_mode_supported is False:
            return [False]
        if self.json_mode_supported is True:
            return [True]
        return [True, False]

    def _openai(self, messages, json_mode, temperature, max_tokens=None) -> LLMResult:
        last_error: Exception | None = None
        for use_json in self._json_attempts(json_mode):
            payload = {
                "model": self.model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens or self.num_predict,
            }
            if use_json:
                payload["response_format"] = {"type": "json_object"}
            req = urllib.request.Request(
                self.base_url + "/v1/chat/completions",
                data=json.dumps(payload).encode(),
                headers=self._openai_headers(),
            )
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    data = json.loads(r.read())
            except urllib.error.HTTPError as e:
                body = e.read().decode("utf-8", "replace")[:500]
                last_error = LLMHTTPError(e.code, body)
                if e.code == 400 and use_json:
                    continue  # retry without response_format
                raise last_error from e

            if use_json:
                self.json_mode_supported = True
            elif json_mode:
                self.json_mode_supported = False

            usage = data.get("usage", {}) or {}
            oc = usage.get("opencode", {}) or {}
            choice = (data.get("choices") or [{}])[0]
            return LLMResult(
                content=choice.get("message", {}).get("content", ""),
                prompt_tokens=usage.get("prompt_tokens"),
                completion_tokens=usage.get("completion_tokens"),
                raw=data,
                cost_usd=usage.get("cost"),
                billing_source=oc.get("billing_source"),
                allowance=oc.get("allowance"),
                finish_reason=choice.get("finish_reason"),
            )
        raise last_error or RuntimeError("LLM request failed")

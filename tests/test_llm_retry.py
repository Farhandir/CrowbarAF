"""Transient-error retries in LLMClient and failed calls excluded from verdict coverage."""
from __future__ import annotations

import io
import json
import urllib.error

import pytest

import llm_layer.client as client_mod
from llm_layer.client import LLMClient, LLMHTTPError
from llm_layer.types import FunctionInfo, FunctionSummary
from llm_layer.verdict import compute_verdict

OK_BODY = {"choices": [{"message": {"content": "{}"}, "finish_reason": "stop"}],
           "usage": {"prompt_tokens": 3, "completion_tokens": 2}}


class _Resp:
    def __init__(self, payload: dict) -> None:
        self._data = json.dumps(payload).encode()

    def read(self) -> bytes:
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        return None


def _http_error(code: int, retry_after: str | None = None) -> urllib.error.HTTPError:
    headers = {"Retry-After": retry_after} if retry_after is not None else {}
    return urllib.error.HTTPError("http://x/v1/chat/completions", code, "err", headers,
                                  io.BytesIO(b'{"error":"rate_limit"}'))


def _client(**kw) -> tuple[LLMClient, list[float]]:
    c = LLMClient(provider="openai", model="m", base_url="http://x", json_mode_supported=True, **kw)
    waits: list[float] = []
    c._sleep = waits.append
    return c, waits


def _script(monkeypatch, outcomes: list) -> list:
    calls: list = []

    def fake_urlopen(req, timeout=None):
        calls.append(req)
        item = outcomes[len(calls) - 1]
        if isinstance(item, Exception):
            raise item
        return _Resp(item)

    monkeypatch.setattr(client_mod.urllib.request, "urlopen", fake_urlopen)
    return calls


def test_429_is_retried_then_succeeds(monkeypatch):
    calls = _script(monkeypatch, [_http_error(429), _http_error(429), OK_BODY])
    c, waits = _client()
    res = c.chat([{"role": "user", "content": "hi"}])
    assert res.prompt_tokens == 3
    assert len(calls) == 3
    assert len(waits) == 2 and all(0 < w <= client_mod.MAX_BACKOFF_SECONDS for w in waits)


def test_retry_after_header_is_respected(monkeypatch):
    _script(monkeypatch, [_http_error(429, retry_after="7"), OK_BODY])
    c, waits = _client()
    c.chat([{"role": "user", "content": "hi"}])
    assert waits == [7.0]


def test_retry_after_is_capped(monkeypatch):
    _script(monkeypatch, [_http_error(503, retry_after="3600"), OK_BODY])
    c, waits = _client()
    c.chat([{"role": "user", "content": "hi"}])
    assert waits == [client_mod.MAX_BACKOFF_SECONDS]


def test_gives_up_after_max_retries(monkeypatch):
    calls = _script(monkeypatch, [_http_error(429)] * 3)
    c, waits = _client(max_retries=2)
    with pytest.raises(LLMHTTPError) as exc:
        c.chat([{"role": "user", "content": "hi"}])
    assert exc.value.status == 429
    assert len(calls) == 3 and len(waits) == 2


@pytest.mark.parametrize("code", [401, 403, 404, 500])
def test_non_transient_errors_are_not_retried(monkeypatch, code):
    calls = _script(monkeypatch, [_http_error(code)])
    c, waits = _client()
    with pytest.raises(LLMHTTPError):
        c.chat([{"role": "user", "content": "hi"}])
    assert len(calls) == 1 and waits == []


def test_connection_error_is_retried(monkeypatch):
    calls = _script(monkeypatch, [urllib.error.URLError("reset"), OK_BODY])
    c, waits = _client()
    c.chat([{"role": "user", "content": "hi"}])
    assert len(calls) == 2 and len(waits) == 1


def test_factory_reads_max_retries(monkeypatch):
    from llm_layer.factory import from_env
    monkeypatch.setenv("CROWBAR_LLM_MAX_RETRIES", "1")
    assert from_env().max_retries == 1


# --------------------------------------------------------------------------- #
# verdict: failed placeholders do not count as analyzed
# --------------------------------------------------------------------------- #
def _fn(offset: str) -> FunctionInfo:
    return FunctionInfo(offset=offset, name="f", c_code="int f(){return 1;}")


def _failed(offset: str) -> FunctionSummary:
    return FunctionSummary(offset=offset, summary="(could not be analyzed)", analysis_failed=True)


def test_failed_calls_are_not_counted_as_analyzed():
    fns = [_fn(f"0x{i}") for i in range(10)]
    summaries = {"0x0": FunctionSummary(offset="0x0", summary="s", suspicious=False)}
    summaries.update({f"0x{i}": _failed(f"0x{i}") for i in range(1, 10)})
    v = compute_verdict(fns, [], summaries, analysis_failures=[f"0x{i}: LLMHTTPError" for i in range(1, 10)])
    assert v["coverage"]["analyzed"] == 1
    assert v["coverage"]["failed"] == 9
    assert v["coverage"]["ratio"] == 0.1
    assert v["counts"]["failed_functions"] == 9
    assert v["verdict"] == "unknown"


def test_omitted_batch_functions_lower_coverage_even_without_failure_list():
    # A batch answer that silently drops functions must not reach no_evidence.
    fns = [_fn(f"0x{i}") for i in range(4)]
    summaries = {"0x0": FunctionSummary(offset="0x0", summary="s", suspicious=False)}
    summaries.update({f"0x{i}": _failed(f"0x{i}") for i in range(1, 4)})
    v = compute_verdict(fns, [], summaries)
    assert v["coverage"]["ratio"] == 0.25
    assert v["verdict"] == "unknown"

"""Batched LLM summary tests (no network)."""
from __future__ import annotations

import json

from llm_layer.batch import build_batch_context, summarize_batch
from llm_layer.client import LLMResult
from llm_layer.pipeline import analyze
from llm_layer.tokens import DEFAULT_COUNTER
from llm_layer.types import Finding, FunctionInfo


def _fn(offset: str, code: str = "int f(){return 1;}") -> FunctionInfo:
    return FunctionInfo(offset=offset, name="f" + offset, c_code=code)


class BatchClient:
    def __init__(self, offsets: list[str] | None = None, omit: str | None = None) -> None:
        self.offsets = offsets
        self.omit = omit
        self.calls = 0
        self.messages: list[list[dict]] = []

    def chat(self, messages, json_mode=True, temperature=0.0, max_tokens=None):
        self.calls += 1
        self.messages.append(messages)
        offsets = self.offsets or ["0x1", "0x2"]
        funcs = [
            {
                "offset": off,
                "summary": "opens a socket",
                "suspicious": True,
                "confidence": "medium",
                "behaviors": ["network"],
                "claims": [{"claim": "socket", "evidence": "return 1"}],
                "suggested_name": "open_socket",
            }
            for off in offsets if off != self.omit
        ]
        return LLMResult(content=json.dumps({"functions": funcs}),
                         prompt_tokens=100, completion_tokens=50, finish_reason="stop")


def setup_function() -> None:
    DEFAULT_COUNTER.chars_per_token = 4.0
    DEFAULT_COUNTER.samples = 0


def test_build_batch_context_has_one_findings_block():
    fns = [_fn("0x1"), _fn("0x2")]
    findings = [Finding(source="floss", kind="string", value="http://192.0.2.1/gate", address=None)]
    text, stats = build_batch_context(fns, findings, budget_tokens=1000)
    assert text.count("FINDINGS") == 1
    assert "http://192.0.2.1/gate" in text
    assert stats["functions"] == 2


def test_summarize_batch_returns_each_function():
    fns = [_fn("0x1"), _fn("0x2")]
    summaries, res, stats = summarize_batch(BatchClient(), fns, [], budget_tokens=1000)
    assert set(summaries) == {"0x1", "0x2"}
    assert summaries["0x1"].suspicious is True
    assert res.prompt_tokens == 100
    assert stats["batch_size"] == 2
    assert stats["json_ok"] is True


def test_summarize_batch_missing_function_is_unknown_not_benign():
    fns = [_fn("0x1"), _fn("0x2")]
    summaries, _, _ = summarize_batch(BatchClient(omit="0x2"), fns, [], budget_tokens=1000)
    assert summaries["0x2"].suspicious is None
    assert summaries["0x2"].summary == ""


def test_analyze_batch_uses_one_call_for_two_functions():
    client = BatchClient()
    res = analyze([_fn("0x1"), _fn("0x2")], [], client, budget_tokens=1000, batch_size=2)
    assert client.calls == 1
    assert res.calls == 1
    assert set(res.summaries) == {"0x1", "0x2"}
    assert res.total_prompt_tokens == 100
    assert res.total_completion_tokens == 50


def test_analyze_batch_trace_counts_each_function():
    client = BatchClient()
    res = analyze([_fn("0x1"), _fn("0x2")], [], client, budget_tokens=1000, batch_size=2)
    assert res.trace is not None
    totals = res.trace.totals
    assert totals["functions_total"] == 2
    assert totals["functions_analyzed"] == 2
    assert totals["coverage"] == 1.0
    assert totals["verified_claims"] == 2


def test_analyze_single_pass_makes_one_call():
    client = BatchClient()
    res = analyze([_fn("0x1"), _fn("0x2")], [], client, budget_tokens=1000,
                  batch_size=1, single_pass=True)
    assert client.calls == 1
    assert res.calls == 1
    assert set(res.summaries) == {"0x1", "0x2"}
    assert res.trace.totals["functions_total"] == 2

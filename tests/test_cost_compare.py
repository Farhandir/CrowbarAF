"""Cost-only naive-vs-Crowbar comparison tests."""
from __future__ import annotations

import json
from pathlib import Path

from experiments.cost_compare import measure, naive_prompt


def test_naive_prompt_contains_functions_and_findings():
    state = {
        "sample": {"sha256": "abc", "file_type": "ELF", "arch": "x86-64"},
        "source_code": [{"offset": "0x1", "name": "f", "c_code": "int f() { return 1; }"}],
        "findings": [{"source": "floss", "kind": "url", "value": "http://x"}],
    }
    prompt = naive_prompt(state)
    assert "int f()" in prompt
    assert "http://x" in prompt


def test_measure_uses_trace_prompt_tokens():
    state = {
        "sample": {"sha256": "abc", "file_type": "ELF", "arch": "x86-64"},
        "source_code": [{"offset": "0x1", "name": "f", "c_code": "x" * 4000}],
        "findings": [],
        "verdict": {"verdict": "needs_review", "coverage": {"ratio": 1.0}},
    }
    trace = {"totals": {"prompt_tokens": 100, "completion_tokens": 20, "tokens_total": 120}}
    row = measure(state, trace, context_tokens=1000)
    assert row["functions"] == 1
    assert row["naive_prompt_tokens_est"] > 1000
    assert row["naive_fits_context"] is False
    assert row["crowbar_prompt_tokens"] == 100
    assert row["prompt_token_savings"] is not None

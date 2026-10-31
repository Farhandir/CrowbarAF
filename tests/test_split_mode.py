"""Split VM/host mode: deterministic state and host-side LLM stage."""
from __future__ import annotations

import os

import pytest

import nodes
from state import AgentState, DecompiledFunction, Finding
import host_analyze as ha


def _state() -> AgentState:
    return AgentState(
        file_path="/vm/sample.bin",
        source_code=[
            DecompiledFunction(offset="0x401000", name="payload", c_code="int f(){return 0;}",
                               priority=7),
        ],
        findings=[
            Finding(source="floss", kind="url",
                    value="http://198.51.100.7/gate.php", address=""),
        ],
    )


def test_ai_reverser_skips_without_llm(monkeypatch):
    monkeypatch.setenv("CROWBAR_SKIP_LLM", "1")
    # If the skip check were missing, this would try to create a client and
    # likely fail; the return must be the empty graph update.
    assert nodes.ai_reverser_agent(AgentState(file_path="x")) == {}


def test_db_writer_skips_without_db(monkeypatch):
    monkeypatch.setenv("CROWBAR_SKIP_DB", "1")
    assert nodes.db_writer_node(_state()) == {}


def test_state_roundtrip_and_permissions(tmp_path, monkeypatch):
    state = _state()
    path = tmp_path / "state.json"
    path.write_text(state.model_dump_json(indent=2), encoding="utf-8")

    loaded = ha.load_state(path)
    assert loaded.file_path == state.file_path
    assert loaded.source_code[0].offset == "0x401000"

    out = tmp_path / "out" / "state_llm.json"
    written = ha.write_state(loaded, out)
    assert written == out
    assert out.is_file()
    assert (out.stat().st_mode & 0o777) == 0o600


def test_load_state_rejects_invalid_json(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid state JSON"):
        ha.load_state(p)


def test_analyze_state_merges_verdict_and_report(monkeypatch):
    captured = {}
    updated_fn = DecompiledFunction(offset="0x401000", name="payload",
                                    c_code="int f(){return 0;}", priority=7,
                                    llm_summary="connects to C2")

    def fake_reverser(state, client=None, budget_tokens=6000):
        captured["client"] = client
        captured["budget"] = budget_tokens
        return {
            "source_code": [updated_fn],
            "intent_analysis": "1 suspicious function",
            "verdict": {"verdict": "malicious", "coverage": {"total": 1, "analyzed": 1}},
        }

    def fake_supervisor(state):
        captured["verdict"] = state.verdict
        return {"analysis_report": "# report"}

    monkeypatch.setattr(ha, "run_reverser", fake_reverser)
    monkeypatch.setattr(ha, "run_supervisor", fake_supervisor)
    client = object()
    out = ha.analyze_state(_state(), client=client, budget_tokens=1234, report=True)

    assert captured["client"] is client
    assert captured["budget"] == 1234
    assert out.verdict["verdict"] == "malicious"
    assert out.analysis_report == "# report"
    assert out.source_code[0].llm_summary == "connects to C2"


def test_analyze_state_can_skip_report(monkeypatch):
    def fake_reverser(state, client=None, budget_tokens=6000):
        return {"source_code": state.source_code, "intent_analysis": "x",
                "verdict": {"verdict": "needs_review"}}

    monkeypatch.setattr(ha, "run_reverser", fake_reverser)
    out = ha.analyze_state(_state(), client=object(), report=False)
    assert out.verdict["verdict"] == "needs_review"
    assert out.analysis_report == ""


def test_host_cli_refuses_skip_llm_env(monkeypatch, capsys):
    monkeypatch.setenv("CROWBAR_SKIP_LLM", "1")
    rc = ha.main(["--state", "missing.json", "--out", "x.json"])
    assert rc == 2
    assert "CROWBAR_SKIP_LLM" in capsys.readouterr().err

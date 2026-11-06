"""Split VM/host mode: deterministic state and host-side LLM stage."""
from __future__ import annotations

import os

import pytest

import db
import nodes
from state import AgentState, DecompiledFunction, Finding, SampleInfo
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
    # POSIX permission bits are not enforced on Windows (chmod is silently a no-op); skip there.
    if os.name != "nt":
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


# --------------------------------------------------------------------------- #
# host_analyze --db: writing split-mode results to SQLite
# --------------------------------------------------------------------------- #
SHA = "ab" * 32


def _merged_state() -> AgentState:
    """State after the host-side LLM and policy stages (verdict, report, llm_summary)."""
    return AgentState(
        file_path="/vm/sample.bin",
        sample=SampleInfo(sha256=SHA, file_type="ELF", route="native", packer="none", arch="x86-64"),
        source_code=[
            DecompiledFunction(offset="0x401000", name="payload", c_code="int f(){return 0;}",
                               priority=7, callees=["0x401100"], iocs=["http://198.51.100.7/gate.php"],
                               llm_summary="connects to C2"),
            DecompiledFunction(offset="0x401100", name="helper", c_code="void h(){}", priority=1),
        ],
        findings=[
            Finding(source="floss", kind="url", value="http://198.51.100.7/gate.php", address=""),
            Finding(source="yara", kind="rule", value="Evil_Rule", address="0x401000"),
        ],
        analysis_report="# supervisor report",
        verdict={"verdict": "malicious", "coverage": {"total": 2, "analyzed": 2}},
    )


def test_persist_state_writes_everything(tmp_path):
    path = str(tmp_path / "split.db")
    saved = ha.persist_state(_merged_state(), path)
    assert saved["sha256"] == SHA
    assert saved["functions"] == 2 and saved["findings"] == 2 and saved["llm_claims"] is True

    detail = db.get_sample_details(SHA, path)
    assert detail["sample"]["file_type"] == "ELF"
    assert detail["verdict"]["verdict"] == "malicious"
    assert detail["supervisor_report"] == "# supervisor report"
    by_off = {f["offset"]: f for f in detail["functions"]}
    assert by_off["0x401000"]["llm_summary"] == "connects to C2"
    assert by_off["0x401000"]["callees"] == ["0x401100"]

    listing = db.get_all_samples(path)
    assert [s["sha256"] for s in listing] == [SHA]
    assert listing[0]["verdict"]["verdict"] == "malicious" and listing[0]["has_report"] is True


def test_persist_state_requires_sha256(tmp_path):
    path = str(tmp_path / "x.db")
    with pytest.raises(ValueError, match="sha256"):
        ha.persist_state(AgentState(file_path="x"), path)
    assert not os.path.exists(path)  # no keyless row / empty DB is created


def _write_state_file(tmp_path) -> str:
    p = tmp_path / "state.json"
    p.write_text(_merged_state().model_dump_json(), encoding="utf-8")
    return str(p)


def test_cli_db_flag_persists(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(ha, "analyze_state", lambda st, **kw: st)  # no LLM
    dbp = str(tmp_path / "cli.db")
    rc = ha.main(["--state", _write_state_file(tmp_path), "--out", str(tmp_path / "o.json"),
                  "--db", dbp])
    assert rc == 0
    assert "saved to" in capsys.readouterr().err
    assert db.get_sample_details(SHA, dbp)["verdict"]["verdict"] == "malicious"


def test_cli_db_flag_without_value_uses_default_path(tmp_path, monkeypatch):
    default = str(tmp_path / "crowbaraf.db")
    monkeypatch.setattr(db, "DEFAULT_DB_PATH", default)
    monkeypatch.setattr(ha, "analyze_state", lambda st, **kw: st)
    rc = ha.main(["--state", _write_state_file(tmp_path), "--out", str(tmp_path / "o.json"), "--db"])
    assert rc == 0
    assert db.get_sample_details(SHA, default) is not None


def test_cli_without_db_flag_does_not_touch_db(tmp_path, monkeypatch):
    default = str(tmp_path / "crowbaraf.db")
    monkeypatch.setattr(db, "DEFAULT_DB_PATH", default)
    monkeypatch.setattr(ha, "analyze_state", lambda st, **kw: st)
    rc = ha.main(["--state", _write_state_file(tmp_path), "--out", str(tmp_path / "o.json")])
    assert rc == 0
    assert not os.path.exists(default)


def test_cli_db_failure_returns_error_but_keeps_state_file(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(ha, "analyze_state", lambda st, **kw: st)
    out = tmp_path / "o.json"
    state_no_sha = AgentState(file_path="x")
    p = tmp_path / "s.json"
    p.write_text(state_no_sha.model_dump_json(), encoding="utf-8")
    rc = ha.main(["--state", str(p), "--out", str(out), "--db", str(tmp_path / "d.db")])
    assert rc == 1
    assert "sha256" in capsys.readouterr().err
    assert out.is_file()  # the LLM result is not lost because of a DB error

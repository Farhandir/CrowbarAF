"""sandbox/validate_state.py: size, schema, POSIX permissions, llm_summary, key leak."""
from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "validate_state", Path(__file__).resolve().parent.parent / "sandbox" / "validate_state.py"
)
vs = importlib.util.module_from_spec(_SPEC)
sys.modules["validate_state"] = vs  # required by @dataclass inside the module
_SPEC.loader.exec_module(vs)

posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are not enforced on Windows")
FAKE_KEY = "sk-" + "aB3dE5fG7hJ9kL1m" * 2  # synthetic, 35 chars


def _state(**over) -> dict:
    state = {
        "file_path": "/vm/sample.bin",
        "sample": {"sha256": "ab" * 32, "file_type": "ELF"},
        "route_flag": "native",
        "findings": [{"source": "floss", "kind": "url", "value": "http://198.51.100.7/x"}],
        "source_code": [
            {"offset": "0x1", "name": "main", "c_code": "int main(){}", "llm_summary": "entry point"},
            {"offset": "0x2", "name": "f", "c_code": "void f(){}", "llm_summary": "helper"},
        ],
    }
    state.update(over)
    return state


def _write(tmp_path, state, name="state.json", mode=0o600) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(state), encoding="utf-8")
    os.chmod(p, mode)  # no-op on Windows
    return p


@pytest.fixture(autouse=True)
def _no_env_key(monkeypatch):
    monkeypatch.delenv("CROWBAR_LLM_API_KEY", raising=False)


# --------------------------------------------------------------------------- #
# success
# --------------------------------------------------------------------------- #
def test_valid_state_passes(tmp_path):
    res = vs.validate_state(_write(tmp_path, _state()))
    assert res.ok and bool(res) and res.errors == []
    assert res.functions == 2 and res.findings == 1


def test_state_without_functions_passes(tmp_path):
    assert vs.validate_state(_write(tmp_path, _state(source_code=[])))


def test_route_flag_may_be_null(tmp_path):
    assert vs.validate_state(_write(tmp_path, _state(route_flag=None)))


# --------------------------------------------------------------------------- #
# 1) size
# --------------------------------------------------------------------------- #
def test_size_over_limit_rejected_before_parsing(tmp_path):
    p = tmp_path / "big.json"
    p.write_text("{" + " " * 4096 + "}", encoding="utf-8")  # would be invalid schema, never parsed
    res = vs.validate_state(p, max_mb=0.001)
    assert not res.ok
    assert len(res.errors) == 1 and res.errors[0].startswith("size:")


def test_default_limit_is_50_mb():
    assert vs.MAX_STATE_MB == 50
    assert vs.build_parser().get_default("max_mb") == 50


def test_size_check_uses_file_size(tmp_path):
    p = _write(tmp_path, _state())
    assert vs.check_size(p, 50) == []
    assert vs.check_size(p, 0.0001)  # ~100 bytes limit


# --------------------------------------------------------------------------- #
# 2) schema
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("missing", ["sample", "route_flag", "file_path"])
def test_missing_required_key_rejected(tmp_path, missing):
    state = _state()
    del state[missing]
    res = vs.validate_state(_write(tmp_path, state))
    assert not res.ok
    assert any(f"missing required key '{missing}'" in e for e in res.errors)


def test_invalid_json_rejected(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    res = vs.validate_state(p)
    assert not res.ok and "invalid JSON" in res.errors[0]


def test_top_level_must_be_object(tmp_path):
    res = vs.validate_state(_write(tmp_path, ["a", "b"]))
    assert not res.ok and "must be an object" in res.errors[0]


def test_wrong_types_rejected(tmp_path):
    res = vs.validate_state(_write(tmp_path, _state(sample="x", source_code={})))
    assert any("'sample' must be an object" in e for e in res.errors)
    assert any("'source_code' must be a list" in e for e in res.errors)


def test_missing_file_rejected(tmp_path):
    res = vs.validate_state(tmp_path / "nope.json")
    assert not res.ok and res.errors[0].startswith("file:")


# --------------------------------------------------------------------------- #
# 3) POSIX permissions
# --------------------------------------------------------------------------- #
@posix_only
@pytest.mark.parametrize("mode", [0o600, 0o400])
def test_owner_only_permissions_pass(tmp_path, mode):
    assert vs.validate_state(_write(tmp_path, _state(), mode=mode))


@posix_only
@pytest.mark.parametrize("mode", [0o644, 0o640, 0o660, 0o666, 0o604, 0o700])
def test_open_permissions_rejected(tmp_path, mode):
    res = vs.validate_state(_write(tmp_path, _state(), mode=mode))
    assert not res.ok
    assert any(e.startswith("permissions:") for e in res.errors)


def _fake_path(mode: int):
    return SimpleNamespace(stat=lambda: SimpleNamespace(st_mode=stat.S_IFREG | mode))


def test_permission_check_with_mocked_posix(monkeypatch):
    """Platform independent: pretend to be POSIX and feed fake stat results."""
    monkeypatch.setattr(vs, "_is_windows", lambda: False)
    assert vs.check_permissions(_fake_path(0o600)) == []
    assert vs.check_permissions(_fake_path(0o400)) == []
    for bad in (0o644, 0o640, 0o620, 0o606, 0o666, 0o777, 0o700):
        errs = vs.check_permissions(_fake_path(bad))
        assert errs and errs[0].startswith("permissions:"), oct(bad)


def test_permission_check_skipped_on_windows(monkeypatch, tmp_path):
    monkeypatch.setattr(vs, "_is_windows", lambda: True)
    assert vs.check_permissions(_fake_path(0o777)) is None  # skipped, never an error
    res = vs.validate_state(_write(tmp_path, _state(), mode=0o777))
    assert res.ok
    assert any("permissions" in s for s in res.skipped)


def test_open_permissions_fail_validate_state_when_posix(monkeypatch, tmp_path):
    """validate_state wires a permission failure into the result (platform independent)."""
    monkeypatch.setattr(vs, "check_permissions", lambda p: ["permissions: mode 0644 is too open"])
    res = vs.validate_state(_write(tmp_path, _state()))
    assert not res.ok and any(e.startswith("permissions:") for e in res.errors)


# --------------------------------------------------------------------------- #
# 4) llm_summary
# --------------------------------------------------------------------------- #
def test_empty_llm_summary_rejected(tmp_path):
    state = _state()
    state["source_code"][1]["llm_summary"] = ""
    res = vs.validate_state(_write(tmp_path, state))
    assert not res.ok
    err = next(e for e in res.errors if e.startswith("llm_summary:"))
    assert "1/2" in err and "0x2" in err


def test_whitespace_only_summary_rejected(tmp_path):
    state = _state()
    state["source_code"][0]["llm_summary"] = "   \n"
    assert not vs.validate_state(_write(tmp_path, state))


def test_non_string_or_missing_summary_rejected_even_when_empty_allowed(tmp_path):
    state = _state()
    state["source_code"][0]["llm_summary"] = None
    del state["source_code"][1]["llm_summary"]
    res = vs.validate_state(_write(tmp_path, state), allow_empty_summaries=True)
    assert not res.ok
    assert sum("non-string llm_summary" in e for e in res.errors) == 2


def test_allow_empty_summaries_for_deterministic_vm_state(tmp_path):
    state = _state()
    for fn in state["source_code"]:
        fn["llm_summary"] = ""
    p = _write(tmp_path, state)
    assert not vs.validate_state(p)
    assert vs.validate_state(p, allow_empty_summaries=True)


# --------------------------------------------------------------------------- #
# 5) key leak
# --------------------------------------------------------------------------- #
def test_sk_key_in_nested_value_rejected(tmp_path):
    state = _state()
    state["source_code"][0]["c_code"] = f'const char *k = "{FAKE_KEY}";'
    res = vs.validate_state(_write(tmp_path, state))
    assert not res.ok
    leak = next(e for e in res.errors if e.startswith("key leak:"))
    assert "source_code[0].c_code" in leak
    assert FAKE_KEY not in "\n".join(res.errors)  # the secret is never echoed


def test_sk_key_in_dict_key_or_deep_list_rejected(tmp_path):
    assert not vs.validate_state(_write(tmp_path, _state(extra={FAKE_KEY: 1})))
    assert not vs.validate_state(_write(tmp_path, _state(extra=[[["x", {"a": [FAKE_KEY]}]]])))


def test_sk_false_positives_are_not_flagged(tmp_path):
    state = _state(extracted_strings=["disk-cache-size-limit-reached", "task-1234567890123456789",
                                      "risk-assessment-score-high", "sk-short", "ask-me-anything-now-please"])
    assert vs.validate_state(_write(tmp_path, state))


def test_env_key_value_rejected(tmp_path):
    secret = "my-very-private-token-0123"
    state = _state()
    state["intent_analysis"] = f"debug dump: auth={secret} end"
    res = vs.validate_state(_write(tmp_path, state), env={"CROWBAR_LLM_API_KEY": secret})
    assert not res.ok
    assert any("CROWBAR_LLM_API_KEY" in e for e in res.errors)
    assert secret not in "\n".join(res.errors)


def test_env_key_read_from_os_environ(tmp_path, monkeypatch):
    monkeypatch.setenv("CROWBAR_LLM_API_KEY", "another-private-token-9876")
    state = _state(intent_analysis="x another-private-token-9876 y")
    assert not vs.validate_state(_write(tmp_path, state))


def test_unset_or_trivial_env_key_does_not_reject_everything(tmp_path):
    p = _write(tmp_path, _state())
    assert vs.validate_state(p, env={})
    assert vs.validate_state(p, env={"CROWBAR_LLM_API_KEY": "a"})  # too short to be meaningful
    assert vs.validate_state(p, env={"CROWBAR_LLM_API_KEY": ""})


def test_key_leak_checked_even_when_other_checks_fail(tmp_path):
    state = _state(extra=FAKE_KEY)
    del state["route_flag"]
    res = vs.validate_state(_write(tmp_path, state))
    assert any(e.startswith("schema:") for e in res.errors)
    assert any(e.startswith("key leak:") for e in res.errors)


# --------------------------------------------------------------------------- #
# CLI / exit codes
# --------------------------------------------------------------------------- #
def test_cli_exit_0_on_valid(tmp_path, capsys):
    p = _write(tmp_path, _state())
    assert vs.main([str(p)]) == 0
    assert capsys.readouterr().out.startswith("OK")


def test_cli_exit_1_on_invalid_and_prints_reasons(tmp_path, capsys):
    p = _write(tmp_path, _state(extra=FAKE_KEY))
    assert vs.main([str(p)]) == 1
    cap = capsys.readouterr()
    assert "FAIL" in cap.out and "key leak" in cap.err
    assert FAKE_KEY not in cap.out + cap.err


def test_cli_exit_1_if_any_file_fails(tmp_path):
    good = _write(tmp_path, _state(), name="good.json")
    bad = tmp_path / "bad.json"
    bad.write_text("nope", encoding="utf-8")
    assert vs.main([str(good), str(bad)]) == 1
    assert vs.main([str(good)]) == 0


def test_cli_allow_empty_summaries_flag(tmp_path):
    state = _state()
    state["source_code"][0]["llm_summary"] = ""
    p = _write(tmp_path, state)
    assert vs.main([str(p)]) == 1
    assert vs.main(["--allow-empty-summaries", str(p)]) == 0


def test_cli_max_mb_option(tmp_path):
    p = _write(tmp_path, _state())
    assert vs.main(["--max-mb", "0.0001", str(p)]) == 1


def test_validates_real_pipeline_state_shape(tmp_path):
    """A real AgentState dump (all default fields) must satisfy the schema."""
    from state import AgentState, DecompiledFunction
    st = AgentState(file_path="/x/s.bin",
                    source_code=[DecompiledFunction(offset="0x1", name="f", llm_summary="ok")])
    p = tmp_path / "real.json"
    p.write_text(st.model_dump_json(), encoding="utf-8")
    os.chmod(p, 0o600)
    assert vs.validate_state(p)

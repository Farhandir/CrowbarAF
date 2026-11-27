"""Verdict handling of static script findings (source="script"); synthetic data only."""
from dataclasses import replace
from types import SimpleNamespace

from llm_layer.c2_triage import collect_c2_candidates
from llm_layer.nodes import run_reverser
from llm_layer.types import Finding
from llm_layer.verdict import SCRIPT_UNSUPPORTED_REASON, compute_verdict, is_critical_finding

COMBO = Finding(source="script", kind="combo", value="Download-Write-Execute", confidence=0.8)
URL = Finding(source="script", kind="url", value="http://203.0.113.9/p.js", confidence=0.7)
DOMAIN = Finding(source="script", kind="domain", value="example.net", confidence=0.5)


def test_script_url_is_critical_c2_but_combo_and_domain_are_not():
    assert is_critical_finding(URL)
    assert not is_critical_finding(COMBO)
    assert not is_critical_finding(DOMAIN)


def test_combo_alone_needs_review_with_script_signal():
    v = compute_verdict([], [COMBO], {})
    assert v["verdict"] == "needs_review"
    assert v["counts"]["signals"] == ["script"]


def test_url_alone_is_not_two_signals():
    v = compute_verdict([], [URL], {})
    assert v["verdict"] == "needs_review"
    assert "script" not in v["counts"]["signals"]
    assert v["counts"]["signals"] == ["c2"]


def test_combo_plus_script_url_is_capped_at_review():
    v = compute_verdict([], [COMBO, URL], {})
    assert v["verdict"] == "needs_review"
    assert set(v["counts"]["signals"]) == {"c2", "script"}
    assert any("independent source" in r for r in v["reasons"])


def test_combo_plus_independent_yara_is_malicious():
    yara = Finding(source="yara", kind="rule", value="Some_Family", confidence=1.0)
    v = compute_verdict([], [COMBO, yara], {})
    assert v["verdict"] == "malicious"


def test_script_combo_plus_floss_c2_is_not_script_only():
    floss = Finding(source="floss", kind="url", value="http://198.51.100.7/g", confidence=0.7)
    v = compute_verdict([], [COMBO, floss], {})
    assert v["verdict"] == "malicious"


def test_domain_alone_is_not_a_signal():
    v = compute_verdict([], [DOMAIN], {})
    assert v["verdict"] == "unknown"
    assert v["counts"]["signals"] == []


def test_unverified_script_url_cannot_support_malicious():
    url = replace(URL, verified=False)
    v = compute_verdict([], [COMBO, url], {})
    assert v["verdict"] != "malicious"


def test_script_url_is_a_triage_candidate():
    assert [c["token"] for c in collect_c2_candidates([URL], [])] == [URL.value]


def _state(route, findings):
    return SimpleNamespace(source_code=[], findings=findings,
                           sample=SimpleNamespace(route=route, packer="none"))


def test_script_route_without_functions_adds_unknown_reason():
    out = run_reverser(_state("script", []))
    assert out["verdict"]["verdict"] == "unknown"
    assert SCRIPT_UNSUPPORTED_REASON in out["verdict"]["unknown_reasons"]


def test_other_route_has_no_script_reason():
    out = run_reverser(_state("native", []))
    assert SCRIPT_UNSUPPORTED_REASON not in out["verdict"]["unknown_reasons"]


def test_script_reason_not_added_to_non_unknown_verdict():
    out = run_reverser(_state("script", [COMBO]))
    assert out["verdict"]["verdict"] == "needs_review"
    assert SCRIPT_UNSUPPORTED_REASON not in out["verdict"]["unknown_reasons"]


class _FakeClient:
    def __init__(self):
        self.calls = 0

    def chat(self, messages, json_mode=True, temperature=0.0, max_tokens=None):
        from llm_layer.client import LLMResult
        self.calls += 1
        content = '{"candidates": [{"id": "c1", "label": "plausible_c2", "reason": "raw IP"}]}'
        return LLMResult(content=content, prompt_tokens=10, completion_tokens=5)


def test_script_route_runs_llm_c2_triage_lazily(monkeypatch):
    import llm_layer.nodes as ln
    fake = _FakeClient()
    monkeypatch.setattr(ln, "from_env", lambda: fake)
    out = run_reverser(_state("script", [COMBO, URL]))
    assert fake.calls == 1
    review = out["verdict"]["c2_review"]
    assert review["llm"] is True and review["candidates"][0]["label"] == "plausible_c2"
    assert out["verdict"]["verdict"] == "needs_review"  # advisory: verdict unchanged


def test_no_candidates_creates_no_client(monkeypatch):
    import llm_layer.nodes as ln

    def boom():
        raise AssertionError("client must not be created")
    monkeypatch.setattr(ln, "from_env", boom)
    run_reverser(_state("script", [COMBO]))


def test_client_failure_keeps_deterministic_labels(monkeypatch):
    import llm_layer.nodes as ln

    def fail():
        raise RuntimeError("no key")
    monkeypatch.setattr(ln, "from_env", fail)
    out = run_reverser(_state("script", [COMBO, URL]))
    review = out["verdict"]["c2_review"]
    assert review["llm"] is False and len(review["candidates"]) == 1


def test_triage_disabled_creates_no_client(monkeypatch):
    import llm_layer.nodes as ln
    monkeypatch.setenv("CROWBAR_LLM_C2_TRIAGE", "0")
    monkeypatch.setattr(ln, "from_env", lambda: (_ for _ in ()).throw(AssertionError("no client")))
    run_reverser(_state("script", [COMBO, URL]))

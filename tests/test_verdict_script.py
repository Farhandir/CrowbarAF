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


def test_combo_plus_url_is_malicious():
    v = compute_verdict([], [COMBO, URL], {})
    assert v["verdict"] == "malicious"
    assert set(v["counts"]["signals"]) == {"c2", "script"}


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

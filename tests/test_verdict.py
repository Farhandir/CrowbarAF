"""Authority policy with finding integrity: unverified critical findings never mean 'malicious'."""
from __future__ import annotations

import pytest

from llm_layer.nodes import _to_findings
from llm_layer.types import Finding, FunctionInfo, FunctionSummary
from llm_layer.verdict import apply_fail_closed, compute_verdict, finding_id, is_critical_finding
from state import AgentState
from state import Finding as StateFinding

C2 = "http://192.0.2.1:4444/gate.php"


def _fn(offset="0x1"):
    return FunctionInfo(offset=offset, name="f", c_code="int f(){return 1;}")


def _benign(offset="0x1"):
    return FunctionSummary(offset=offset, summary="s", suspicious=False)


def _susp(offset="0x1"):
    return FunctionSummary(offset=offset, summary="s", suspicious=True)


def _c2(verified=True, **kw):
    return Finding(source="floss", kind="url", value=C2, verified=verified, **kw)


def _yara(verified=True):
    return Finding(source="yara", kind="rule", value="Malware.X", verified=verified)


# --------------------------------------------------------------------------- #
# baseline (verified) behaviour is unchanged
# --------------------------------------------------------------------------- #
def test_verified_defaults_to_true():
    assert Finding(source="floss", kind="url", value=C2).verified is True
    assert StateFinding(source="floss", kind="url", value=C2).verified is True


def test_verified_yara_plus_verified_c2_is_malicious():
    v = compute_verdict([_fn()], [_yara(), _c2()], {"0x1": _benign()})
    assert v["verdict"] == "malicious"
    assert v["counts"]["unverified_critical"] == 0


# --------------------------------------------------------------------------- #
# unverified critical IoC -> needs_review, never malicious
# --------------------------------------------------------------------------- #
def test_unverified_critical_ioc_alone_is_needs_review_not_malicious():
    v = compute_verdict([_fn()], [_c2(verified=False)], {"0x1": _benign()})
    assert v["verdict"] == "needs_review"
    assert v["counts"]["unverified_critical"] == 1
    assert v["counts"]["critical_findings"] == 0
    assert any("unverified" in r for r in v["reasons"])
    assert [f["value"] for f in v["unverified_findings"]] == [C2]
    assert v["critical_findings"] == []


def test_unverified_c2_cannot_corroborate_yara_into_malicious():
    """yara + (fake) C2 would be 'malicious' (two signals); the unverified C2 must not count."""
    v = compute_verdict([_fn()], [_yara(), _c2(verified=False)], {"0x1": _benign()})
    assert v["verdict"] == "needs_review"
    assert v["counts"]["signals"] == ["yara"]
    assert v["counts"]["two_signal"] is False


def test_unverified_c2_cannot_corroborate_llm_or_capa():
    capa = Finding(source="capa", kind="rule", value="encrypt data")
    v = compute_verdict([_fn()], [capa, _c2(verified=False)], {"0x1": _benign()})
    assert v["verdict"] == "needs_review"          # not malicious (c2 + capa would be)
    v = compute_verdict([_fn()], [_c2(verified=False)], {"0x1": _susp()})
    assert v["verdict"] == "needs_review"          # single llm signal only


def test_verified_corroboration_still_malicious_and_unverified_is_ignored():
    findings = [_yara(), _c2(verified=True), Finding(source="floss", kind="ip", value="203.0.113.9",
                                                      verified=False)]
    v = compute_verdict([_fn()], findings, {"0x1": _benign()})
    assert v["verdict"] == "malicious"
    assert v["counts"]["unverified_critical"] == 1
    assert any("ignored as evidence" in r for r in v["reasons"])


def test_unverified_critical_never_malicious_in_single_signal_mode():
    """Even with require_two_signals=False an unverified finding is not high authority."""
    v = compute_verdict([_fn()], [_c2(verified=False)], {"0x1": _benign()}, require_two_signals=False)
    assert v["verdict"] == "needs_review"


def test_unverified_finding_lifts_no_evidence_to_needs_review():
    covered = compute_verdict([_fn()], [], {"0x1": _benign()})
    assert covered["verdict"] == "no_evidence"
    flagged = compute_verdict([_fn()], [_c2(verified=False)], {"0x1": _benign()})
    assert flagged["verdict"] == "needs_review"  # worst case; never malicious, never 'clean'


def test_unverified_finding_lifts_unknown_to_needs_review():
    # low coverage would be 'unknown'; the unverified finding must still be reviewed
    v = compute_verdict([_fn("0x1"), _fn("0x2")], [_c2(verified=False)], {"0x1": _benign()})
    assert v["coverage"]["ratio"] == 0.5
    assert v["verdict"] == "needs_review"


# --------------------------------------------------------------------------- #
# fail-closed: LLM says clean + unverified critical finding
# --------------------------------------------------------------------------- #
def test_llm_clean_with_unverified_critical_is_overridden_to_unknown_then_needs_review():
    fn = _fn()
    findings = [_c2(verified=False)]  # address=None -> global, relevant to every function
    summary = apply_fail_closed(_benign(), fn, findings)
    assert summary.suspicious is None and summary.fail_closed is True
    assert "unverified" in " ".join(summary.behaviors)

    v = compute_verdict([fn], findings, {"0x1": summary})
    assert v["verdict"] == "needs_review"          # worst case, not malicious
    assert v["counts"]["fail_closed"] == 1


def test_verified_critical_keeps_original_fail_closed_note():
    summary = apply_fail_closed(_benign(), _fn(), [_c2(verified=True)])
    assert summary.fail_closed is True
    assert "fail-closed: critical finding present" in summary.behaviors


def test_is_critical_finding_is_independent_of_verified():
    """Must-include selection still sees it (the LLM may inspect it); only the verdict discounts it."""
    assert is_critical_finding(_c2(verified=False)) is True


@pytest.mark.parametrize("verified", [True, False])
def test_yara_unverified_flag_also_discounted(verified):
    v = compute_verdict([_fn()], [_yara(verified=verified), _c2()], {"0x1": _benign()})
    assert v["verdict"] == ("malicious" if verified else "needs_review")


# --------------------------------------------------------------------------- #
# plumbing: state.Finding -> llm Finding, ids
# --------------------------------------------------------------------------- #
def test_state_findings_carry_verified_and_id_to_llm_layer():
    state = AgentState(file_path="x", findings=[
        StateFinding(source="floss", kind="url", value=C2, finding_id="abcd1234", verified=False),
        StateFinding(source="yara", kind="rule", value="R"),
    ])
    a, b = _to_findings(state)
    assert (a.verified, a.finding_id) == (False, "abcd1234")
    assert (b.verified, b.finding_id) == (True, "")


def test_verdict_reuses_state_finding_id():
    f = _c2(verified=False, finding_id="abcd1234")
    v = compute_verdict([_fn()], [f], {"0x1": _benign()})
    assert v["unverified_findings"][0]["id"] == "abcd1234"
    assert finding_id(_c2()).startswith("f_")  # legacy id when none was assigned

"""S13: address-less critical findings fail-close only the functions they are tied to.

Synthetic data only.
"""
from llm_layer.types import Finding, FunctionInfo, FunctionSummary
from llm_layer.verdict import apply_fail_closed, compute_verdict, linked_critical_ids

C2 = "http://203.0.113.9/gate.php"


def _fn(offset, code="", iocs=None):
    return FunctionInfo(offset=offset, name="f" + offset, c_code=code, iocs=iocs or [])


def _benign(offset):
    return FunctionSummary(offset=offset, summary="formats a string", suspicious=False)


def _c2(**kw):
    return Finding(source="floss", kind="url", value=C2, confidence=0.9, **kw)


def test_linked_by_ioc_list_is_localized():
    user = _fn("0x10", iocs=[C2])
    other = _fn("0x20", code="int x = 1;")
    findings = [_c2()]
    linked = linked_critical_ids(findings, [user, other])
    assert len(linked) == 1
    assert apply_fail_closed(_benign("0x10"), user, findings, linked).suspicious is None
    assert apply_fail_closed(_benign("0x20"), other, findings, linked).suspicious is False


def test_linked_by_value_in_code_is_localized():
    user = _fn("0x10", code=f'connect("{C2}");')
    other = _fn("0x20", code="return 0;")
    findings = [_c2()]
    linked = linked_critical_ids(findings, [user, other])
    assert apply_fail_closed(_benign("0x10"), user, findings, linked).fail_closed is True
    assert apply_fail_closed(_benign("0x20"), other, findings, linked).fail_closed is False


def test_unlinked_finding_stays_global():
    a, b = _fn("0x10", code="a"), _fn("0x20", code="b")
    findings = [_c2()]
    linked = linked_critical_ids(findings, [a, b])
    assert linked == frozenset()
    for fn in (a, b):
        assert apply_fail_closed(_benign(fn.offset), fn, findings, linked).suspicious is None


def test_without_linked_the_old_global_rule_applies():
    user = _fn("0x10", iocs=[C2])
    other = _fn("0x20")
    findings = [_c2()]
    assert apply_fail_closed(_benign("0x20"), other, findings).suspicious is None
    assert apply_fail_closed(_benign("0x10"), user, findings).suspicious is None


def test_addressed_finding_unchanged():
    a, b = _fn("0x10"), _fn("0x20")
    findings = [Finding(source="yara", kind="rule", value="Fam", address="0x10")]
    linked = linked_critical_ids(findings, [a, b])
    assert apply_fail_closed(_benign("0x10"), a, findings, linked).suspicious is None
    assert apply_fail_closed(_benign("0x20"), b, findings, linked).suspicious is False


def test_mixed_linked_and_unlinked_globals():
    user = _fn("0x10", iocs=[C2])
    other = _fn("0x20")
    unlinked = Finding(source="floss", kind="url", value="http://198.51.100.7/x", confidence=0.9)
    findings = [_c2(), unlinked]
    linked = linked_critical_ids(findings, [user, other])
    # The unlinked one is still global, so "other" is fail-closed by it.
    assert apply_fail_closed(_benign("0x20"), other, findings, linked).suspicious is None


def test_file_verdict_still_counts_the_c2_signal():
    user = _fn("0x10", code="x", iocs=[C2])
    other = _fn("0x20", code="y")
    findings = [_c2(), Finding(source="capa", kind="capability", value="send HTTP request",
                               confidence=0.9)]
    linked = linked_critical_ids(findings, [user, other])
    summaries = {fn.offset: apply_fail_closed(_benign(fn.offset), fn, findings, linked)
                 for fn in (user, other)}
    v = compute_verdict([user, other], findings, summaries)
    assert "c2" in v["counts"]["signals"]
    assert v["verdict"] == "malicious"

"""report.py testleri (saf mantık, LLM gerekmez)."""
from __future__ import annotations

import report


def _state(findings=None, functions=None, capabilities=None):
    return {
        "sample": {"sha256": "abc", "file_type": "ELF", "arch": "x86-64",
                   "packer": "none", "route": "native"},
        "findings": findings or [],
        "capabilities": capabilities or {},
        "source_code": functions or [],
        "extracted_strings": [],
    }


def test_belirsiz_when_no_evidence():
    rep = report.build(_state())
    assert rep["verdict"]["level"] == "unknown"
    assert rep["verdict"]["has_deterministic_evidence"] is False
    assert any("unknown" in x.lower() for x in rep["limitations"])


def test_deterministic_evidence_raises_verdict():
    rep = report.build(_state(findings=[{"source": "yara", "kind": "rule", "value": "Test", "address": ""}]))
    assert rep["verdict"]["level"] == "high"
    assert rep["tools"]["yara"][0]["rule"] == "Test"


def test_floss_only_is_medium():
    rep = report.build(_state(findings=[{"source": "floss", "kind": "url", "value": "http://x"}]))
    assert rep["verdict"]["level"] == "medium"
    assert "hxxp://x" in rep["tools"]["floss"]["ioc_findings"]  # defang edilmiş (tıklanamaz)
    assert "http://x" not in rep["tools"]["floss"]["ioc_findings"]


def test_capa_and_imports_grouped():
    rep = report.build(_state(
        findings=[{"source": "import_combo", "kind": "import_combo", "value": "Process Injection Combo"}],
        capabilities={"matched_rules": ["inject code"], "mitre_attack": ["T1055"], "malware_behavior": []},
    ))
    assert rep["tools"]["imports"]["combos"] == ["Process Injection Combo"]
    assert rep["tools"]["capa"]["matched_rules"] == ["inject code"]
    assert rep["tools"]["capa"]["mitre_attack"] == ["T1055"]


def test_ghidra_inventory_and_priority():
    rep = report.build(_state(functions=[
        {"offset": "0x2", "name": "low", "priority": 0, "size": 10, "c_code": "int f(){}"},
        {"offset": "0x1", "name": "hi", "priority": 5, "size": 20, "c_code": "int g(){}", "callees": ["0x2"]},
    ]))
    g = rep["tools"]["ghidra"]
    assert g["function_count"] == 2
    assert g["decompiled"] == 2
    assert g["call_edges"] == 1
    assert g["prioritized"][0]["name"] == "hi"
    assert g["prioritized"][0]["interesting"] is True


def test_markdown_has_tool_sections_and_ai_separate():
    trace = {"functions": [{"offset": "0x1", "name": "f",
                            "claims": [{"text": "iddia", "evidence": "e", "status": "unverified"}]}],
             "totals": {"functions_analyzed": 1}}
    rep = report.build(_state(findings=[{"source": "yara", "kind": "rule", "value": "T"}]), trace)
    md = report.render_markdown(rep)
    for sec in ("## 1) YARA", "## 6) Ghidra", "AI commentary"):
        assert sec in md
    # heading-based groups (no emoji)
    assert "Unverified claims" in md
    assert "⚠️" not in md
    assert rep["counts"]["ai_unverified"] == 1


def test_markdown_groups_file_level_claims():
    trace = {"functions": [{"offset": "0x1", "name": "f",
                            "claims": [{"text": "file evidence", "evidence": "x", "status": "file_level"}]}],
             "totals": {"functions_analyzed": 1}}
    rep = report.build(_state(), trace)
    md = report.render_markdown(rep)
    assert "File-level evidence" in md
    assert rep["counts"]["ai_file_level"] == 1


def test_render_json_roundtrip():
    rep = report.build(_state())
    import json
    assert json.loads(report.render_json(rep))["identity"]["sha256"] == "abc"


def test_state_verdict_is_rendered_with_coverage():
    st = _state()
    st["verdict"] = {
        "verdict": "unknown",
        "coverage": {"analyzed": 2, "total": 5, "ratio": 0.4},
        "unknown_reasons": ["coverage 40% < 80%"],
        "next_actions": ["analyze skipped functions"],
    }
    rep = report.build(st)
    assert rep["verdict"]["state"] == "unknown"
    assert rep["verdict"]["coverage"]["ratio"] == 0.4
    md = report.render_markdown(rep)
    assert "State" in md
    assert "40%" in md


# --------------------------------------------------------------------------- #
# verified == False -> "(Unverified)" uyarısı
# --------------------------------------------------------------------------- #
def test_unverified_ioc_is_flagged_in_markdown_html_and_json():
    rep = report.build(_state(findings=[
        {"source": "floss", "kind": "url", "value": "http://real.example/a", "verified": True},
        {"source": "floss", "kind": "url", "value": "http://ghost.example/b", "verified": False},
        {"source": "floss", "kind": "ip", "value": "10.9.8.7"},  # eski state: alan yok -> doğrulanmış sayılır
    ]))
    assert rep["tools"]["floss"]["ioc_unverified"] == ["hxxp://ghost[.]example/b"]

    md = report.render_markdown(rep)
    lines = {ln for ln in md.splitlines() if ln.startswith("- **IoC:**")}
    flagged = [ln for ln in lines if "(Unverified)" in ln]
    assert len(flagged) == 1 and "hxxp://ghost[.]example/b" in flagged[0]
    assert len(lines) == 3  # diğer iki IoC uyarısız
    assert "(Unverified)" in report.render_html(rep)
    assert "ioc_unverified" in report.render_json(rep)


def test_no_unverified_marker_when_everything_is_verified():
    rep = report.build(_state(findings=[{"source": "floss", "kind": "url", "value": "http://x", "verified": True}]))
    assert rep["tools"]["floss"]["ioc_unverified"] == []
    assert "(Unverified)" not in report.render_markdown(rep)


def test_render_html_is_a_real_escaped_report():
    rep = report.build(_state(findings=[
        {"source": "floss", "kind": "url", "value": "http://x/<script>alert(1)</script>"}
    ]))
    out = report.render_html(rep)
    assert "<html" in out and "CrowbarAF Analysis Report" in out
    assert "<script>" not in out
    assert "&lt;script&gt;" in out
    assert "<pre>" not in out or "FLOSS" in out
    assert "⚠️" not in out

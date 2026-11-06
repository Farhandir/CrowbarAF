"""IoC defanging (analyst safety): utils, db.get_sample_details, API and report.py."""
from __future__ import annotations

import pytest

import db
import report
from state import AgentState, DecompiledFunction, Finding, SampleInfo
from utils import defang_finding, defang_ioc, defang_iocs, defang_text


@pytest.mark.parametrize("raw, expected", [
    ("http://evil.example.com/gate.php", "hxxp://evil.example[.]com/gate.php"),
    ("https://evil.example.com/a.b?x=1.2", "hxxps://evil.example[.]com/a.b?x=1.2"),
    ("HTTPS://Evil.Example.com", "hxxps://Evil.Example[.]com"),
    ("http://1.1.1.1/x", "hxxp://1.1.1[.]1/x"),
    ("http://198.51.100.7:4444/gate.php", "hxxp://198.51.100[.]7:4444/gate.php"),
    ("https://user:pw@evil.example.com:8443/p", "hxxps://user:pw@evil.example[.]com:8443/p"),
    ("ftp://files.evil.example.org/a", "fxp://files.evil.example[.]org/a"),
    ("1.1.1.1", "1.1.1[.]1"),
    ("198.51.100.7:80", "198.51.100[.]7:80"),
    ("evil.com", "evil[.]com"),
    ("a.b.evil.com", "a.b.evil[.]com"),
    ("evil.com/path/file.php", "evil[.]com/path/file.php"),
    ("user@evil.example.com", "user@evil.example[.]com"),
    ("http://[::1]:8080/x", "hxxp://[::1]:8080/x"),
    ("http://localhost/x", "hxxp://localhost/x"),
])
def test_defang_ioc(raw, expected):
    assert defang_ioc(raw) == expected


@pytest.mark.parametrize("raw", [
    "", "no dots here", r"HKLM\Software\Microsoft\Windows", r"C:\Windows\evil.dll",
    "two words.here", "plainword",
])
def test_defang_leaves_non_network_values(raw):
    assert defang_ioc(raw) == raw


@pytest.mark.parametrize("raw", [
    "http://evil.example.com/a", "https://1.1.1.1/x", "1.1.1.1", "evil.com",
    "user@evil.example.com", "ftp://a.b.org/x",
])
def test_defang_is_idempotent(raw):
    once = defang_ioc(raw)
    assert defang_ioc(once) == once


def test_defang_never_leaves_a_clickable_scheme():
    out = defang_ioc("http://evil.example.com/a")
    assert "http://" not in out and "https://" not in out


def test_defang_non_string_is_untouched():
    assert defang_ioc(None) is None  # type: ignore[arg-type]
    assert defang_iocs(None) == []
    assert defang_iocs(["http://a.b/x", 5]) == ["hxxp://a[.]b/x", 5]


def test_defang_text_urls_and_ips():
    text = "beacon to https://evil.example.com/a and 198.51.100.7, see http://x.org."
    out = defang_text(text)
    assert "hxxps://evil.example[.]com/a" in out
    assert "198.51.100[.]7," in out
    assert "http://" not in out and "https://" not in out
    assert defang_text(out) == out  # idempotent


def test_defang_finding_only_network_kinds():
    assert defang_finding({"kind": "url", "value": "http://a.b/x"})["value"] == "hxxp://a[.]b/x"
    assert defang_finding({"kind": "ip", "value": "1.2.3.4"})["value"] == "1.2.3[.]4"
    assert defang_finding({"kind": "registry", "value": r"HKLM\a.b"})["value"] == r"HKLM\a.b"
    assert defang_finding({"kind": "rule", "value": "x.y"})["value"] == "x.y"
    orig = {"kind": "url", "value": "http://a.b/x"}
    defang_finding(orig)
    assert orig["value"] == "http://a.b/x"  # returns a copy, the input is not modified


# --------------------------------------------------------------------------- #
# DB / API: the raw value is stored; the read path defangs it
# --------------------------------------------------------------------------- #
SHA = "cd" * 32
URL = "http://198.51.100.7/gate.php"


def _state() -> AgentState:
    return AgentState(
        file_path="/x/s.bin",
        sample=SampleInfo(sha256=SHA, file_type="ELF"),
        source_code=[DecompiledFunction(offset="0x1", name="f", c_code=f'puts("{URL}");',
                                        iocs=[URL, "evil.example.com"])],
        findings=[
            Finding(source="floss", kind="url", value=URL),
            Finding(source="floss", kind="ip", value="198.51.100.7"),
            Finding(source="yara", kind="rule", value="Evil.Rule"),
        ],
    )


def test_get_sample_details_defangs_iocs_but_db_keeps_raw(tmp_path):
    path = str(tmp_path / "d.db")
    db.save_analysis(_state(), path)

    detail = db.get_sample_details(SHA, path)
    values = {f["kind"]: f["value"] for f in detail["findings"]}
    assert values["url"] == "hxxp://198.51.100[.]7/gate.php"
    assert values["ip"] == "198.51.100[.]7"
    assert values["rule"] == "Evil.Rule"          # non-network IoCs are left untouched
    assert detail["functions"][0]["iocs"] == ["hxxp://198.51.100[.]7/gate.php", "evil.example[.]com"]

    import sqlite3
    raw = sqlite3.connect(path).execute("SELECT value FROM findings WHERE kind='url'").fetchone()[0]
    assert raw == URL  # raw value in the database (for LLM matching)


def test_api_detail_returns_defanged_iocs(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    import main

    path = str(tmp_path / "api.db")
    monkeypatch.setattr(db, "DEFAULT_DB_PATH", path)
    db.save_analysis(_state(), path)
    res = TestClient(main.app).get(f"/api/samples/{SHA}")
    assert res.status_code == 200
    body = res.text
    assert "hxxp://198.51.100[.]7/gate.php" in body
    # findings/iocs must not contain raw, clickable URLs (c_code is decompiler output)
    data = res.json()
    for f in data["findings"]:
        assert "http://" not in f["value"]
    for fn in data["functions"]:
        assert all("http://" not in i for i in fn["iocs"])


# --------------------------------------------------------------------------- #
# report.py
# --------------------------------------------------------------------------- #
def _report_state() -> dict:
    return {
        "sample": {"sha256": SHA},
        "findings": [
            {"source": "floss", "kind": "url", "value": URL},
            {"source": "floss", "kind": "ip", "value": "198.51.100.7"},
            {"source": "pe_metadata", "kind": "version_info", "value": "Comments: see https://evil.example.com/x"},
        ],
        "extracted_strings": [f"connect {URL} now"],
        "verdict": {"verdict": "needs_review", "reasons": [f"C2-like {URL}"],
                    "next_actions": ["block 198.51.100.7"]},
        "source_code": [],
    }


def test_report_defangs_markdown_html_and_json():
    trace = {"functions": [{"offset": "0x1", "name": "f",
                            "claims": [{"status": "unverified", "text": f"talks to {URL}"}]}]}
    rep = report.build(_report_state(), trace)

    for rendered in (report.render_markdown(rep), report.render_html(rep), report.render_json(rep)):
        assert "http://" not in rendered and "https://" not in rendered
        assert "198.51.100.7" not in rendered
        assert "[.]" in rendered

    md = report.render_markdown(rep)
    assert "hxxp://198.51.100[.]7/gate.php" in md
    assert "hxxps://evil.example[.]com/x" in md
    assert "block 198.51.100[.]7" in md


def test_report_from_db_roundtrip_is_defanged(tmp_path, monkeypatch):
    path = str(tmp_path / "r.db")
    monkeypatch.setattr(db, "DEFAULT_DB_PATH", path)
    db.save_analysis(_state(), path)
    md = report.render_markdown(report.build(report._from_db(SHA)))
    assert "http://" not in md and "198.51.100.7" not in md
    assert "hxxp://198.51.100[.]7/gate.php" in md

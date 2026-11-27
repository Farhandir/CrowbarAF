"""Token-based C2 detection and the strict LLM-only high-confidence tier."""
from __future__ import annotations

import pytest

from llm_layer import verdict
from llm_layer.types import Finding, FunctionInfo, FunctionSummary
from llm_layer.verdict import c2_like_tokens, compute_verdict, is_critical_finding

MANIFEST = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">'
    '<application xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">'
    '<assemblyIdentity version="1.0.0.0"/>'
    "</application></assembly>"
)


def _fn(offset: str) -> FunctionInfo:
    return FunctionInfo(offset=offset, name="f", c_code="int f(){return 1;}")


def _summary(offset: str, suspicious: bool, summary: str = "s",
             behaviors: list[str] | None = None) -> FunctionSummary:
    return FunctionSummary(offset=offset, summary=summary,
                           suspicious=suspicious, behaviors=list(behaviors or []))


def _analyzed(summaries: dict[str, FunctionSummary]) -> list[FunctionInfo]:
    return [_fn(offset) for offset in summaries]


@pytest.fixture
def policy(monkeypatch):
    """Pin the tier thresholds so environment variables cannot change the outcome."""
    monkeypatch.setattr(verdict, "LLM_MIN_SUSPICIOUS", 3)
    monkeypatch.setattr(verdict, "LLM_MIN_BEHAVIORS", 3)
    monkeypatch.setattr(verdict, "LLM_MIN_COVERAGE", 0.6)
    monkeypatch.setattr(verdict, "LLM_MIN_ANALYZED", 20)


# --------------------------------------------------------------------------- #
# c2_like_tokens: benign noise from manifests / versions / infrastructure
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("value", [
    MANIFEST,
    "http://nsis.sf.net/NSIS_Error",
    "1.1.0.0",
    "8.0.5.0",
    "224.0.0.251",
    "127.0.0.1",
    "0.0.0.0",
    "http://www.w3.org/2001/XMLSchema",
    "FileVersion 6.1.7601.17514",
    "FileVersion 6.1.7601.175",
    "v2.4.1.3",
])
def test_c2_like_tokens_ignores_benign_values(value):
    assert c2_like_tokens(value) == []


def test_c2_like_tokens_ignores_longer_dotted_or_numeric_sequences():
    assert c2_like_tokens("1.2.3.4.5") == []
    assert c2_like_tokens("311.2.3.4") == []


# --------------------------------------------------------------------------- #
# c2_like_tokens: real endpoints survive
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("value, expected", [
    ("http://192.0.2.1:4444/gate.php", ["http://192.0.2.1:4444/gate.php"]),
    ("203.0.113.9/new.php", ["203.0.113.9"]),
    ("connect to 10.0.0.5", ["10.0.0.5"]),
    ("https://evil.example.net/a", ["https://evil.example.net/a"]),
    ("http://198.51.100.7/x", ["http://198.51.100.7/x"]),
])
def test_c2_like_tokens_returns_real_endpoint(value, expected):
    assert c2_like_tokens(value) == expected


def test_c2_like_tokens_mixed_returns_only_the_real_url():
    value = ('xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings" '
             'endpoint="http://evil.example.net/a"')
    assert c2_like_tokens(value) == ["http://evil.example.net/a"]


def test_c2_like_tokens_deduplicates_and_strips_trailing_punctuation():
    assert c2_like_tokens("http://198.51.100.7/x") == ["http://198.51.100.7/x"]
    assert c2_like_tokens(
        "see http://evil.example.net/a), then http://evil.example.net/a."
    ) == ["http://evil.example.net/a"]


# --------------------------------------------------------------------------- #
# is_critical_finding / compute_verdict use the token detection
# --------------------------------------------------------------------------- #
def test_manifest_floss_finding_is_not_critical_but_c2_url_is():
    assert is_critical_finding(Finding(source="floss", kind="string", value=MANIFEST)) is False
    assert is_critical_finding(
        Finding(source="floss", kind="url", value="http://192.0.2.1:4444/gate.php")
    ) is True


def test_manifest_only_floss_finding_does_not_add_a_c2_signal():
    findings = [
        Finding(source="capa", kind="rule", value="encrypt data"),
        Finding(source="floss", kind="string", value=MANIFEST),
    ]
    result = compute_verdict([_fn("0x1")], findings, {"0x1": _summary("0x1", False)})
    assert result["counts"]["critical_findings"] == 0
    assert "c2" not in result["counts"]["signals"]
    assert result["verdict"] == "needs_review"  # capa stays medium authority


# --------------------------------------------------------------------------- #
# LLM-only tier (Policy C v2)
# --------------------------------------------------------------------------- #
def test_llm_only_tier_small_surface_stays_needs_review(policy):
    summaries = {
        "0x1": _summary("0x1", True, "persist via cron and network beacon"),
        "0x2": _summary("0x2", True, "file drop and process kill"),
        "0x3": _summary("0x3", True, "persist through systemd, file copy"),
        "0x4": _summary("0x4", False),
    }
    result = compute_verdict(_analyzed(summaries), [], summaries)
    assert result["counts"]["llm_high_confidence"] is False
    assert result["verdict"] == "needs_review"
    assert any(
        "LLM-only signal on small surface (4 analyzed function(s) < 20)" in reason
        for reason in result["reasons"]
    )


def test_llm_only_tier_with_enough_analyzed_functions_is_malicious(policy):
    summaries = {
        f"0x{i}": _summary(f"0x{i}", i <= 3, "persist, network and file activity")
        for i in range(1, 26)
    }
    result = compute_verdict(_analyzed(summaries), [], summaries)
    assert result["coverage"]["analyzed"] == 25
    assert result["counts"]["behavior_classes"] >= 3
    assert result["counts"]["llm_high_confidence"] is True
    assert result["verdict"] == "malicious"


def test_llm_only_tier_free_text_behaviors_do_not_inflate_classes(policy):
    summaries = {
        f"0x{i}": _summary(
            f"0x{i}", True, "network activity",
            [f"free text {j}" for j in range(10)],
        )
        for i in range(1, 26)
    }
    result = compute_verdict(_analyzed(summaries), [], summaries)
    assert result["counts"]["behavior_classes"] == 1
    assert result["counts"]["llm_high_confidence"] is False
    assert result["verdict"] != "malicious"


def test_llm_behavior_keywords_use_word_boundaries(policy):
    summaries = {
        f"0x{i}": _summary(f"0x{i}", i <= 3, "initialize profile")
        for i in range(1, 26)
    }
    result = compute_verdict(_analyzed(summaries), [], summaries)
    # "init" must not match "initialize", "file" must not match "profile".
    assert result["counts"]["behavior_classes"] == 0
    assert result["verdict"] != "malicious"


def test_keyword_prefix_matches_inflected_forms_but_not_mid_word():
    from llm_layer.verdict import _keyword_matches
    assert _keyword_matches("persist", "achieves persistence via cron")
    assert _keyword_matches("exec", "remote execution of commands")
    assert _keyword_matches("inject", "process injection")
    assert _keyword_matches("socket", "opens raw sockets")
    assert not _keyword_matches("file", "loads the user profile")
    assert not _keyword_matches("init", "initialize globals")
    assert _keyword_matches("init", "writes an init script")


@pytest.mark.parametrize("value", [
    "http://ocsp.digicert.com0",
    "http://ocsp.digicert.com0A",
    "http://crl3.digicert.com/sha2-assured-cs-g1.crl0L",
    "http://Mozilla/5.0",
    "https://H9",
    "http://crypto/tls:",
    "http://localhost:8080/x",
    "7.4.1.3",
    "1.1.2.1",
    "8.8.8.8",
])
def test_c2_like_tokens_drops_der_tail_fragments_and_single_digit_ips(value):
    assert c2_like_tokens(value) == []


@pytest.mark.parametrize("value, expected", [
    ("http://evil-digicert.com0", ["http://evil-digicert.com0"]),
    ("http://c2.example0.net/a", ["http://c2.example0.net/a"]),
    ("connect 10.1.2.3", ["10.1.2.3"]),
    ("http://[2001:db8::1]/x", ["http://[2001:db8::1]/x"]),
])
def test_c2_like_tokens_keeps_lookalikes_and_multi_digit_ips(value, expected):
    assert c2_like_tokens(value) == expected

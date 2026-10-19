"""LLM katmani saf mantik testleri (LLM cagrisi gerektirmez)."""
from __future__ import annotations

from llm_layer.client import LLMResult
from llm_layer.context import build_function_context, select_functions, select_with_reasons
from llm_layer.pipeline import AnalysisResult, analyze
from llm_layer.tokens import estimate_tokens, truncate_to_tokens
from llm_layer.trace import Tracer
from llm_layer.traverse import scc_order
from llm_layer.types import Claim, Finding, FunctionInfo, FunctionSummary
from llm_layer.verify import verify_claim


# --- tokens ---
def test_estimate_tokens_basic():
    assert estimate_tokens("") == 0
    assert estimate_tokens("abcd") == 1
    assert estimate_tokens("a" * 40) == 10


def test_truncate_keeps_head_and_tail():
    text = "HEAD" + ("x" * 5000) + "TAIL"
    out = truncate_to_tokens(text, 50)
    assert len(out) <= 50 * 4 + 10
    assert out.startswith("HEAD")
    assert out.endswith("TAIL")
    assert "kisaltildi" in out


def test_truncate_noop_when_fits():
    assert truncate_to_tokens("short", 100) == "short"


# --- context ---
def _fn(offset, code="", priority=0, callees=None, is_library=False):
    return FunctionInfo(offset=offset, name="f" + offset, c_code=code,
                        priority=priority, callees=callees or [], is_library=is_library)


def test_select_functions_respects_priority_and_budget():
    low = _fn("0x1", "a" * 4000, priority=0)     # ~1000 token
    high = _fn("0x2", "b" * 400, priority=5)     # ~100 token
    selected = select_functions([low, high], budget_tokens=200)
    assert [f.offset for f in selected] == ["0x2"]


def test_build_context_contains_evidence_and_child_notes():
    fn = _fn("0x401000", "int f(){return 1;}", priority=5)
    findings = [Finding(source="capa", kind="capability", value="inject code", address="0x401000")]
    from llm_layer.types import FunctionSummary
    child = FunctionSummary(offset="0x400000", summary="opens a file")
    text, stats = build_function_context(fn, [child], findings, budget_tokens=1000)
    assert "inject code" in text
    assert "opens a file" in text
    assert "```c" in text
    assert stats["estimated_tokens"] <= 1000


# --- verify ---
def test_verify_observation_when_quote_in_code():
    c = Claim(text="xor decode", evidence="buf[i] ^ key")
    code = "for(i=0;i<n;i++){ buf[i] ^ key; }"
    assert verify_claim(c, code, []) == "verified_observation"


def test_verify_claim_when_matches_finding():
    c = Claim(text="injection", evidence="WriteProcessMemory")
    f = [Finding(source="import", kind="import_combo", value="WriteProcessMemory")]
    assert verify_claim(c, "no code", f) == "verified_claim"


def test_verify_unverified_when_nothing_matches():
    c = Claim(text="does evil", evidence="totally invented evidence")
    assert verify_claim(c, "int main(){return 0;}", []) == "unverified"


# --- traverse ---
def test_scc_order_callee_first():
    f1 = _fn("0x1", callees=["0x2"])
    f2 = _fn("0x2", callees=["0x3"])
    f3 = _fn("0x3")
    order = [o for scc in scc_order([f1, f2, f3]) for o in scc]
    assert order.index("0x3") < order.index("0x2") < order.index("0x1")


def test_scc_order_handles_cycle():
    a = _fn("a", callees=["b"])
    b = _fn("b", callees=["a"])
    c = _fn("c", callees=["a"])
    sccs = scc_order([a, b, c])
    flat = {o: i for i, scc in enumerate(sccs) for o in scc}
    # a ve b ayni SCC'de olmali; c'den once islenmeli
    assert flat["a"] == flat["b"]
    assert flat["a"] < flat["c"]


# --- pipeline (fake client) ---
class FakeClient:
    def chat(self, messages, json_mode=True, temperature=0.0):
        return LLMResult(
            content='{"ozet":"test ozet","supheli":false,"guven":"orta",'
                    '"davranis":["x"],"iddialar":[{"iddia":"i","kanit":"return 1"}],'
                    '"onerilen_isim":"test_fn"}',
            prompt_tokens=10, completion_tokens=5,
        )


def test_analyze_end_to_end_with_fake_client():
    f1 = _fn("0x1", "int f(){return 1;}", callees=["0x2"])
    f2 = _fn("0x2", "int g(){return 1;}")
    res = analyze([f1, f2], [], FakeClient(), budget_tokens=1000)
    assert set(res.summaries) == {"0x1", "0x2"}
    assert res.calls == 2
    assert res.total_prompt_tokens == 20
    assert res.total_completion_tokens == 10
    assert res.summaries["0x1"].suggested_name == "test_fn"


def test_analyze_skips_library_functions():
    lib = _fn("0x9", "int memset(){}", is_library=True)
    fn = _fn("0xa", "int f(){return 1;}")
    res = analyze([lib, fn], [], FakeClient(), budget_tokens=1000)
    assert "0x9" not in res.summaries
    assert "0xa" in res.summaries


# --- dugum entegrasyonu ---
def test_run_reverser_updates_state_and_intent():
    from llm_layer.nodes import run_reverser
    from state import AgentState, DecompiledFunction

    st = AgentState(
        file_path="x",
        source_code=[DecompiledFunction(offset="0x1", name="f", c_code="int f(){return 1;}")],
    )
    out = run_reverser(st, client=FakeClient())
    assert out["source_code"][0].llm_summary == "test ozet"
    assert "fonksiyon ozetlendi" in out["intent_analysis"]


def test_run_supervisor_flags_missing_evidence():
    from llm_layer.nodes import run_supervisor
    from state import AgentState

    report = run_supervisor(AgentState(file_path="x"))["analysis_report"]
    assert "kanit bulunamadi" in report
    assert "belirsiz" in report


# --- iz (trace) ---
def test_select_with_reasons_reports_library_and_budget():
    lib = _fn("0x1", "a" * 10, is_library=True)
    big = _fn("0x2", "b" * 4000)          # ~1000 token, butceye sigmaz
    small = _fn("0x3", "c" * 10)
    selected, skipped = select_with_reasons([lib, big, small], budget_tokens=50)
    reasons = {f.offset: r for f, r in skipped}
    assert reasons.get("0x1") == "library"
    assert reasons.get("0x2") == "budget"
    assert "0x3" in [f.offset for f in selected]


def test_tracer_records_totals_and_saves(tmp_path):
    tr = Tracer(model="m", provider="p", budget_tokens=100)
    tr.skipped(_fn("0x2", "", is_library=True), "library")
    summary = FunctionSummary(
        offset="0x1", summary="x", suspicious=True, confidence="orta",
        claims=[Claim(text="t", evidence="e", status="unverified")],
    )
    tr.analyzed(_fn("0x1", "code"), {"estimated_tokens": 10, "code_truncated": False, "json_ok": True},
                LLMResult(content="", prompt_tokens=5, completion_tokens=2),
                summary, 0.1, [], 0)
    tr.finalize(AnalysisResult(calls=1, total_prompt_tokens=5, total_completion_tokens=2))

    d = tr.to_dict()
    assert d["totals"]["functions_total"] == 2
    assert d["totals"]["functions_analyzed"] == 1
    assert d["totals"]["functions_skipped"] == 1
    assert d["totals"]["skipped_library"] == 1
    assert d["totals"]["unverified_claims"] == 1

    p = tmp_path / "trace.json"
    tr.save(str(p))
    assert p.exists()



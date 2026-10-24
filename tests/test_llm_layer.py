"""LLM katmani saf mantik testleri (LLM cagrisi gerektirmez)."""
from __future__ import annotations

from llm_layer.cache import SummaryCache
from llm_layer.client import LLMResult
from llm_layer.context import build_function_context, select_functions, select_with_reasons
from llm_layer.pipeline import AnalysisResult, analyze
from llm_layer.summarize import summarize_function
from llm_layer.tokens import TokenCounter, estimate_tokens, truncate_to_tokens
from llm_layer.trace import Tracer
from llm_layer.traverse import scc_levels, scc_order
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
    c = Claim(text="injection", evidence="uses WriteProcessMemory to inject")
    f = [Finding(source="import", kind="import_combo", value="WriteProcessMemory")]
    # bulgu fonksiyona YEREL ise (deger koddA geciyor) dogrulanir
    assert verify_claim(c, "h = OpenProcess(); WriteProcessMemory(h, ...);", f,
                        function_offset="0x1") == "verified_claim"


def test_verify_claim_by_address_match():
    c = Claim(text="injection", evidence="inject code")
    f = [Finding(source="capa", kind="capability", value="inject code", address="0x401000")]
    assert verify_claim(c, "int f(){}", f, function_offset="0x401000") == "verified_claim"


def test_verify_global_finding_is_file_level_not_verified():
    """Dosya-seviyesi (adressiz) bulgu, fonksiyonla eslesmiyorsa 'verified' SAYILMAZ; 'file_level' olur."""
    c = Claim(text="matches yara", evidence="Crowbar_Test_Connecting")
    f = [Finding(source="yara", kind="rule", value="Crowbar_Test_Connecting")]
    assert verify_claim(c, "int f(){return 0;}", f, function_offset="0x999") == "file_level"


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
            content='{"summary":"test summary","suspicious":false,"confidence":"medium",'
                    '"behaviors":["x"],"claims":[{"claim":"i","evidence":"return 1"}],'
                    '"suggested_name":"test_fn"}',
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
    assert out["source_code"][0].llm_summary == "test summary"
    assert "functions summarized" in out["intent_analysis"]


def test_run_supervisor_flags_missing_evidence():
    from llm_layer.nodes import run_supervisor
    from state import AgentState

    report = run_supervisor(AgentState(file_path="x"))["analysis_report"]
    assert "no evidence found" in report
    assert "unknown" in report


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


def test_select_with_reasons_min_priority():
    fn = _fn("0x1", "a" * 10, priority=0)
    selected, skipped = select_with_reasons([fn], budget_tokens=100, min_priority=1)
    assert selected == []
    assert skipped and skipped[0][1] == "priority"


def test_analyze_min_priority_skips_low():
    f0 = _fn("0x1", "int f(){return 1;}", priority=0)
    f1 = _fn("0x2", "int g(){return 1;}", priority=5)
    res = analyze([f0, f1], [], FakeClient(), budget_tokens=1000, min_priority=1)
    assert "0x1" not in res.summaries
    assert "0x2" in res.summaries


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


# --- token sayaci ---
def test_token_counter_estimate_and_calibrate():
    tc = TokenCounter(chars_per_token=4.0)
    assert tc.estimate("a" * 40) == 10
    tc.calibrate("a" * 40, 20)          # gercek oran 2 karakter/token
    assert abs(tc.chars_per_token - 2.0) < 0.01
    assert tc.estimate("a" * 40) == 20
    assert tc.samples == 1


# --- JSON retry ---
class FlakyClient:
    def __init__(self):
        self.calls = 0

    def chat(self, messages, json_mode=True, temperature=0.0):
        self.calls += 1
        if self.calls == 1:
            return LLMResult(content="bu JSON degil", prompt_tokens=5, completion_tokens=2)
        return LLMResult(
            content='{"summary":"ok","suspicious":false,"confidence":"medium","behaviors":[],"claims":[],"suggested_name":"x"}',
            prompt_tokens=5, completion_tokens=2)


def test_summarize_retries_on_invalid_json():
    client = FlakyClient()
    summary, res, stats = summarize_function(client, _fn("0x1", "int f(){return 1;}"), [], [], 1000)
    assert client.calls == 2
    assert stats["json_ok"] is True
    assert stats["attempts"] == 2
    assert summary.summary == "ok"


# --- seviyeler (paralellik) ---
def test_scc_levels_chain():
    f1 = _fn("0x1", callees=["0x2"])
    f2 = _fn("0x2", callees=["0x3"])
    f3 = _fn("0x3")
    levels = scc_levels([f1, f2, f3])
    assert len(levels) == 3
    assert [o for scc in levels[0] for o in scc] == ["0x3"]
    assert [o for scc in levels[2] for o in scc] == ["0x1"]


def test_scc_levels_cycle_same_level():
    a = _fn("a", callees=["b"])
    b = _fn("b", callees=["a"])
    c = _fn("c", callees=["a"])
    levels = scc_levels([a, b, c])
    pos = {o: i for i, lvl in enumerate(levels) for scc in lvl for o in scc}
    assert pos["a"] == pos["b"] < pos["c"]


# --- paralel + onbellek ---
def test_analyze_parallel_matches_serial():
    fns = [_fn(f"0x{i}", f"int f{i}(){{return {i};}}") for i in range(6)]
    res = analyze(fns, [], FakeClient(), budget_tokens=1000, max_workers=3)
    assert len(res.summaries) == 6
    assert res.calls == 6
    assert res.total_prompt_tokens == 60


class CountingClient:
    def __init__(self):
        self.calls = 0

    def chat(self, messages, json_mode=True, temperature=0.0):
        self.calls += 1
        return LLMResult(
            content='{"summary":"ok","suspicious":false,"confidence":"medium","behaviors":[],"claims":[],"suggested_name":"x"}',
            prompt_tokens=5, completion_tokens=2)


def test_cache_avoids_second_call(tmp_path):
    client = CountingClient()
    fns = [_fn("0x1", "int f(){return 1;}")]
    cache = SummaryCache(str(tmp_path / "cache.json"))
    r1 = analyze(fns, [], client, budget_tokens=1000, cache=cache)
    assert client.calls == 1 and r1.calls == 1
    r2 = analyze(fns, [], client, budget_tokens=1000, cache=cache)
    assert client.calls == 1          # ikinci kosuda LLM cagrilmadi
    assert r2.cache_hits == 1 and r2.calls == 0


# --- fidelity harness matematigi ---
def test_fidelity_math():
    import importlib.util
    import pathlib

    path = pathlib.Path(__file__).resolve().parents[1] / "experiments" / "fidelity.py"
    spec = importlib.util.spec_from_file_location("fidelity_harness", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    assert mod.fidelity({"a": True, "b": False}, {"a": True, "b": True}) == (0.5, 2)
    assert mod.fidelity({}, {"a": True}) == (None, 0)
    assert mod.fidelity({"a": True}, {"a": True, "b": False}) == (1.0, 1)




# --- findings: pipeline -> LLM katmanı ---
def test_to_findings_reads_state_findings():
    from llm_layer.nodes import _to_findings
    from state import AgentState, Finding as StateFinding

    st = AgentState(
        file_path="x",
        findings=[
            StateFinding(source="capa", kind="rule", value="inject code", address="0x401000"),
            StateFinding(source="yara", kind="rule", value="Emotet", confidence=0.8),
        ],
        # eski alanlar artık kanıt kaynağı değil
        capabilities={"matched_rules": ["ignored"]},
        iocs={"ioc": ["1.2.3.4"]},
    )
    out = _to_findings(st)
    assert [(f.source, f.value, f.address, f.confidence) for f in out] == [
        ("capa", "inject code", "0x401000", 1.0),
        ("yara", "Emotet", None, 0.8),
    ]


def test_run_supervisor_uses_state_findings():
    from llm_layer.nodes import run_supervisor
    from state import AgentState, Finding as StateFinding

    st = AgentState(
        file_path="x",
        findings=[StateFinding(source="yara", kind="rule", value="Emotet")],
        capabilities={"matched_rules": ["ignored"]},
    )
    report = run_supervisor(st)["analysis_report"]
    assert "yara/rule: Emotet" in report
    assert "ignored" not in report
    assert "no evidence found" not in report


def test_to_function_infos_passes_size():
    from llm_layer.nodes import _to_function_infos
    from state import AgentState, DecompiledFunction

    st = AgentState(file_path="x", source_code=[DecompiledFunction(offset="0x1", size=128, c_code="int f(){}")])
    assert _to_function_infos(st)[0].size == 128


def test_to_function_infos_skips_functions_without_code():
    from llm_layer.nodes import _to_function_infos
    from state import AgentState, DecompiledFunction

    st = AgentState(file_path="x", source_code=[
        DecompiledFunction(offset="0x1", c_code="int f(){}"),
        DecompiledFunction(offset="0x2", c_code=""),
        DecompiledFunction(offset="0x3", c_code="   "),
    ])
    assert [f.offset for f in _to_function_infos(st)] == ["0x1"]

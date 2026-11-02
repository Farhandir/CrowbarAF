"""LangGraph dugumlerinin LLM karsiliklari.

nodes.py'deki ai_* fonksiyonlari bu modulu cagirir. Boylece LLM katmani
pipeline kodundan ayri kalir ve test edilebilir.
"""
from __future__ import annotations

from .factory import from_env
from .pipeline import analyze
from .types import Finding, FunctionInfo
from .verdict import compute_verdict


def _to_function_infos(state) -> list[FunctionInfo]:
    out = []
    for d in getattr(state, "source_code", []) or []:
        # Ghidra decompile etmediği (c_code "") çağrı grafiği kayıtları LLM'e gönderilmez
        if not (getattr(d, "c_code", "") or "").strip():
            continue
        out.append(FunctionInfo(
            offset=getattr(d, "offset", ""),
            name=getattr(d, "name", ""),
            c_code=getattr(d, "c_code", ""),
            priority=getattr(d, "priority", 0),
            size=getattr(d, "size", 0),
            is_library=getattr(d, "is_library", False),
            callees=list(getattr(d, "callees", []) or []),
            xrefs=list(getattr(d, "xrefs", []) or []),
            decompile_warnings=list(getattr(d, "decompile_warnings", []) or []),
            iocs=list(getattr(d, "iocs", []) or []),
        ))
    return out


def _to_findings(state) -> list[Finding]:
    """state.findings'i LLM katmanı tipine çevirir (birleştirme pipeline'da yapıldı)."""
    return [
        Finding(
            source=f.source,
            kind=f.kind,
            value=f.value,
            address=f.address or None,  # boş adres = genel (tüm fonksiyonlar için) bulgu
            confidence=f.confidence,
            finding_id=getattr(f, "finding_id", "") or "",
            verified=bool(getattr(f, "verified", True)),
        )
        for f in getattr(state, "findings", []) or []
    ]


def run_reverser(state, client=None, budget_tokens: int = 6000) -> dict:
    """ai_reverser_agent: bottom-up fonksiyon ozetleme."""
    import os
    import time

    functions = _to_function_infos(state)
    findings = _to_findings(state)
    if not functions:
        return {"intent_analysis": "No functions to analyze (empty Ghidra output).",
                "verdict": compute_verdict([], findings, {})}

    client = client or from_env()
    max_workers = int(os.getenv("CROWBAR_LLM_MAX_WORKERS", "1"))
    cache_path = os.getenv("CROWBAR_LLM_CACHE", "")
    cache = None
    if cache_path:
        from .cache import SummaryCache
        cache = SummaryCache(cache_path)
    low_budget = int(os.getenv("CROWBAR_LLM_LOW_PRIORITY_BUDGET", "0")) or None
    min_priority = int(os.getenv("CROWBAR_LLM_MIN_PRIORITY", "0"))
    result = analyze(functions, findings, client, budget_tokens=budget_tokens,
                     max_workers=max_workers, cache=cache,
                     low_priority_budget=low_budget, min_priority=min_priority)

    # llm_summary'leri state'e geri yaz
    updated = []
    for d in state.source_code:
        s = result.summaries.get(d.offset)
        updated.append(d.model_copy(update={"llm_summary": s.summary if s else ""}))

    # iz (trace) kaydet
    trace_path = None
    if result.trace is not None:
        try:
            outdir = os.getenv("CROWBAR_LLM_TRACE_DIR", "runs")
            ts = time.strftime("%Y%m%d-%H%M%S")
            trace_path = result.trace.save(os.path.join(outdir, f"llm_trace_{ts}.json"))
        except Exception:  # noqa: BLE001 - iz kaydi akisi cokertmesin
            trace_path = None

    # niyet analizi: supheli fonksiyonlar + dogrulanmis iddialar
    lines = []
    for off, s in result.summaries.items():
        if s.suspicious:
            lines.append(f"- {s.name_or_offset()} ({off}): {s.summary[:160]}")
    verified = sum(1 for s in result.summaries.values()
                   for c in s.claims if c.status.startswith("verified"))
    unverified = sum(1 for s in result.summaries.values()
                     for c in s.claims if c.status == "unverified")
    intent = (
        f"{result.calls} functions summarized; "
        f"suspicious={sum(1 for s in result.summaries.values() if s.suspicious)}; "
        f"verified claims={verified}, unverified={unverified}; "
        f"tokens={result.token_total()}."
        + (f" Trace: {trace_path}" if trace_path else "")
        + "\n"
        + ("\n".join(lines) if lines else "No suspicious functions found.")
    )
    packer = (getattr(getattr(state, "sample", None), "packer", "") or "").lower()
    packed = packer not in ("", "none", "unknown") and (
        not functions or all(f.is_library for f in functions))
    two_signal = os.getenv("CROWBAR_TWO_SIGNAL_MALICIOUS", "1").strip().lower() \
        not in ("0", "false", "no", "off")
    verdict = compute_verdict(functions, findings, result.summaries,
                              packed=packed, analysis_failures=result.failures,
                              require_two_signals=two_signal)
    return {"source_code": updated, "intent_analysis": intent, "verdict": verdict}


def run_supervisor(state) -> dict:
    """ai_supervisor_agent: deterministic synthesis (evidence vs no-evidence)."""
    summaries = list(getattr(state, "source_code", []) or [])

    evidence = [
        f"{f.source}/{f.kind}: {f.value}" + (f" @ {f.address}" if f.address else "")
        for f in getattr(state, "findings", []) or []
    ]

    summarized = [d for d in summaries if getattr(d, "llm_summary", "")]
    confidence = "high" if evidence else ("medium" if summarized else "low")

    lines = ["# CrowbarAF Analysis Report", ""]
    v = getattr(state, "verdict", {}) or {}
    if v:
        cov = v.get("coverage", {}) or {}
        lines += [
            f"- **Verdict:** `{v.get('verdict', 'unknown')}`",
            f"- **Coverage:** {cov.get('analyzed', 0)}/{cov.get('total', 0)} functions "
            f"({float(cov.get('ratio', 0.0)):.0%})",
        ]
    lines += [
        f"- **Evidence items:** {len(evidence)}",
        f"- **Summarized functions:** {len(summarized)}",
        f"- **Overall confidence:** {confidence}",
    ]
    if v.get("reasons"):
        lines.append("- **Reasons:** " + "; ".join(v["reasons"]))
    if v.get("unknown_reasons"):
        lines.append("- **Unknown because:** " + "; ".join(v["unknown_reasons"]))
    if v.get("next_actions"):
        lines.append("- **Next:** " + "; ".join(v["next_actions"]))
    lines += ["", "## Deterministic evidence"]
    lines += [f"- {e}" for e in evidence] or ["- (no evidence found)"]
    lines += ["", "## Function summaries"]
    lines += [f"- `{d.offset}` {getattr(d, 'name', '')}: {d.llm_summary[:160]}" for d in summarized] \
        or ["- (no summaries)"]
    if not evidence:
        lines += ["", "> **Warning:** No deterministic evidence. This sample is "
                      "'unknown', not 'clean'; manual review is required."]
    return {"analysis_report": "\n".join(lines)}

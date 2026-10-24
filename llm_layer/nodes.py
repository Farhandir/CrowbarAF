"""LangGraph dugumlerinin LLM karsiliklari.

nodes.py'deki ai_* fonksiyonlari bu modulu cagirir. Boylece LLM katmani
pipeline kodundan ayri kalir ve test edilebilir.
"""
from __future__ import annotations

from .factory import from_env
from .pipeline import analyze
from .types import Finding, FunctionInfo


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
        return {"intent_analysis": "Analiz edilecek fonksiyon yok (Ghidra cikisi bos)."}

    client = client or from_env()
    max_workers = int(os.getenv("CROWBAR_LLM_MAX_WORKERS", "1"))
    cache_path = os.getenv("CROWBAR_LLM_CACHE", "")
    cache = None
    if cache_path:
        from .cache import SummaryCache
        cache = SummaryCache(cache_path)
    low_budget = int(os.getenv("CROWBAR_LLM_LOW_PRIORITY_BUDGET", "0")) or None
    result = analyze(functions, findings, client, budget_tokens=budget_tokens,
                     max_workers=max_workers, cache=cache,
                     low_priority_budget=low_budget)

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
        f"{result.calls} fonksiyon ozetlendi; "
        f"supheli={sum(1 for s in result.summaries.values() if s.suspicious)}; "
        f"dogrulanmis iddia={verified}, dogrulanamayan={unverified}; "
        f"token={result.token_total()}."
        + (f" Iz: {trace_path}" if trace_path else "")
        + "\n"
        + ("\n".join(lines) if lines else "Supheli fonksiyon bulunamadi.")
    )
    return {"source_code": updated, "intent_analysis": intent}


def run_supervisor(state) -> dict:
    """ai_supervisor_agent: deterministik sentez (kanit/kanitsiz ayrimi ile)."""
    summaries = list(getattr(state, "source_code", []) or [])

    evidence = [
        f"{f.source}/{f.kind}: {f.value}" + (f" @ {f.address}" if f.address else "")
        for f in getattr(state, "findings", []) or []
    ]

    suspicious = [d for d in summaries if getattr(d, "llm_summary", "")]
    confidence = "yuksek" if evidence else ("orta" if suspicious else "dusuk")

    lines = [
        "# CrowbarAF Analiz Raporu",
        "",
        f"- **Kanit sayisi:** {len(evidence)}",
        f"- **Ozetlenen fonksiyon:** {len(suspicious)}",
        f"- **Genel guven:** {confidence}",
        "",
        "## Deterministik kanit",
    ]
    lines += [f"- {e}" for e in evidence] or ["- (kanit bulunamadi)"]
    lines += ["", "## Fonksiyon ozetleri"]
    lines += [f"- `{d.offset}` {getattr(d, 'name', '')}: {d.llm_summary[:160]}" for d in suspicious] \
        or ["- (ozet yok)"]
    if not evidence:
        lines += ["", "> **Dikkat:** Deterministik kanit yok. Bu dosya icin karar "
                      "'belirsiz'dir; 'temiz' olarak yorumlanmamalidir."]
    return {"analysis_report": "\n".join(lines)}

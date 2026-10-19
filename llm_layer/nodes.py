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
        out.append(FunctionInfo(
            offset=getattr(d, "offset", ""),
            name=getattr(d, "name", ""),
            c_code=getattr(d, "c_code", ""),
            priority=getattr(d, "priority", 0),
            is_library=getattr(d, "is_library", False),
            callees=list(getattr(d, "callees", []) or []),
            xrefs=list(getattr(d, "xrefs", []) or []),
            decompile_warnings=list(getattr(d, "decompile_warnings", []) or []),
        ))
    return out


def _to_findings(state) -> list[Finding]:
    findings: list[Finding] = []
    caps = getattr(state, "capabilities", {}) or {}
    for rule in caps.get("matched_rules", []) or []:
        findings.append(Finding(source="capa", kind="capability", value=str(rule)))
    for tech in caps.get("mitre_attack", []) or []:
        findings.append(Finding(source="capa", kind="attack", value=str(tech)))
    for behavior in caps.get("malware_behavior", []) or []:
        findings.append(Finding(source="capa", kind="mbc", value=str(behavior)))
    for ioc_list in (getattr(state, "iocs", {}) or {}).values():
        for ioc in ioc_list or []:
            findings.append(Finding(source="floss", kind="ioc", value=str(ioc)))
    for hint in getattr(state, "ghidra_hints", []) or []:
        if isinstance(hint, dict) and hint.get("rule"):
            findings.append(Finding(source="capa", kind="capability",
                                    value=str(hint["rule"]), address=hint.get("offset")))
    return findings


def run_reverser(state, client=None, budget_tokens: int = 6000) -> dict:
    """ai_reverser_agent: bottom-up fonksiyon ozetleme."""
    import os
    import time

    functions = _to_function_infos(state)
    findings = _to_findings(state)
    if not functions:
        return {"intent_analysis": "Analiz edilecek fonksiyon yok (Ghidra cikisi bos)."}

    client = client or from_env()
    result = analyze(functions, findings, client, budget_tokens=budget_tokens)

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
    caps = getattr(state, "capabilities", {}) or {}
    iocs = getattr(state, "iocs", {}) or {}
    summaries = list(getattr(state, "source_code", []) or [])

    evidence = []
    for rule in caps.get("matched_rules", []) or []:
        evidence.append(f"capa: {rule}")
    for tech in caps.get("mitre_attack", []) or []:
        evidence.append(f"ATT&CK: {tech}")
    for k, vals in iocs.items():
        for v in vals or []:
            evidence.append(f"IoC ({k}): {v}")

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

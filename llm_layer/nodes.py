"""LLM counterparts of the LangGraph nodes.

The ai_* functions in nodes.py call this module. This keeps the LLM layer
separate from the pipeline code and testable.
"""
from __future__ import annotations

import logging
import os

from .c2_triage import (collect_c2_candidates, deterministic_review, sort_review,
                        triage_c2_candidates)
from .factory import from_env
from .pipeline import analyze
from .types import Finding, FunctionInfo
from .verdict import SCRIPT_UNSUPPORTED_REASON, compute_verdict

logger = logging.getLogger(__name__)


def _c2_triage_enabled() -> bool:
    """Advisory C2 triage is on by default; CROWBAR_LLM_C2_TRIAGE=0 disables it."""
    return os.getenv("CROWBAR_LLM_C2_TRIAGE", "1").strip().lower() not in (
        "0", "false", "no", "off")


def _to_function_infos(state, include_empty: bool = False) -> list[FunctionInfo]:
    out = []
    for d in getattr(state, "source_code", []) or []:
        # Call-graph records Ghidra did not decompile (c_code "") are not sent to
        # the LLM, but they must still count in coverage.
        if not include_empty and not (getattr(d, "c_code", "") or "").strip():
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
    """Convert state.findings to the LLM layer type (merging is done in the pipeline)."""
    return [
        Finding(
            source=f.source,
            kind=f.kind,
            value=f.value,
            address=f.address or None,  # empty address = global finding (applies to all functions)
            confidence=f.confidence,
            finding_id=getattr(f, "finding_id", "") or "",
            verified=bool(getattr(f, "verified", True)),
        )
        for f in getattr(state, "findings", []) or []
    ]


def _c2_review(findings, functions, client, lazy_client: bool = False) -> dict:
    """Advisory C2 candidate review; never changes the verdict.

    With ``lazy_client`` the LLM client is created only when there are candidates and the
    triage is enabled; if it cannot be created the deterministic labels are kept.
    """
    candidates = collect_c2_candidates(findings, functions)
    review = None
    if candidates and _c2_triage_enabled():
        if client is None and lazy_client:
            try:
                client = from_env()
            except Exception as exc:  # noqa: BLE001 - advisory step must not break the verdict
                logger.warning("[c2_triage] no LLM client (%s); deterministic labels only",
                               type(exc).__name__)
        if client is not None:
            review = triage_c2_candidates(candidates, client)
    if review is None:
        review = deterministic_review(candidates)
    return {
        "candidates": sort_review(review["candidates"]),
        "llm": review["llm"],
        "prompt_tokens": review["prompt_tokens"],
        "completion_tokens": review["completion_tokens"],
        "error": review["error"],
    }


def run_reverser(state, client=None, budget_tokens: int = 6000) -> dict:
    """ai_reverser_agent: bottom-up function summarization."""
    import time

    all_functions = _to_function_infos(state, include_empty=True)
    functions = [f for f in all_functions if (f.c_code or "").strip()]
    findings = _to_findings(state)
    if not functions:
        verdict = compute_verdict(all_functions, findings, {})
        route = (getattr(getattr(state, "sample", None), "route", "") or "").lower()
        # Only an unknown verdict is explained by the unsupported format; a review or
        # malicious verdict already rests on the static script findings.
        if (route == "script" and verdict["verdict"] == "unknown"
                and SCRIPT_UNSUPPORTED_REASON not in verdict["unknown_reasons"]):
            verdict["unknown_reasons"].append(SCRIPT_UNSUPPORTED_REASON)
        # Scripts (and empty decompiles) still get the advisory C2 triage; the client is
        # created only when there is something to triage.
        verdict["c2_review"] = _c2_review(findings, all_functions, client, lazy_client=True)
        return {"intent_analysis": "No functions to analyze (empty Ghidra output).",
                "verdict": verdict}

    client = client or from_env()
    max_workers = int(os.getenv("CROWBAR_LLM_MAX_WORKERS", "1"))
    cache_path = os.getenv("CROWBAR_LLM_CACHE", "")
    cache = None
    if cache_path:
        from .cache import SummaryCache
        cache = SummaryCache(cache_path)
    low_budget = int(os.getenv("CROWBAR_LLM_LOW_PRIORITY_BUDGET", "0")) or None
    min_priority = int(os.getenv("CROWBAR_LLM_MIN_PRIORITY", "0"))
    batch_size = int(os.getenv("CROWBAR_LLM_BATCH_SIZE", "1"))
    single_pass = os.getenv("CROWBAR_LLM_SINGLE_PASS", "0").strip().lower() \
        in ("1", "true", "yes", "on")
    single_pass_max = int(os.getenv("CROWBAR_LLM_SINGLE_PASS_MAX", "40"))
    use_single_pass = single_pass and len(functions) <= single_pass_max
    batch_size = max(1, batch_size)
    result = analyze(functions, findings, client, budget_tokens=budget_tokens,
                     max_workers=max_workers, cache=cache,
                     low_priority_budget=low_budget, min_priority=min_priority,
                     batch_size=batch_size, single_pass=use_single_pass)

    # write llm_summary values back to state
    updated = []
    for d in state.source_code:
        s = result.summaries.get(d.offset)
        updated.append(d.model_copy(update={"llm_summary": s.summary if s else ""}))

    # save the trace
    trace_path = None
    if result.trace is not None:
        try:
            outdir = os.getenv("CROWBAR_LLM_TRACE_DIR", "runs")
            ts = time.strftime("%Y%m%d-%H%M%S")
            trace_path = result.trace.save(os.path.join(outdir, f"llm_trace_{ts}.json"))
        except Exception:  # noqa: BLE001 - trace saving must not crash the flow
            trace_path = None

    # intent analysis: suspicious functions + verified claims
    lines = []
    for off, s in result.summaries.items():
        if s.suspicious:
            lines.append(f"- {s.name_or_offset()} ({off}): {s.summary[:160]}")
    verified = sum(1 for s in result.summaries.values()
                   for c in s.claims if c.status.startswith("verified"))
    unverified = sum(1 for s in result.summaries.values()
                     for c in s.claims if c.status == "unverified")
    intent = (
        f"{len(result.summaries)} functions summarized; "
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
    verdict = compute_verdict(all_functions, findings, result.summaries,
                              packed=packed, analysis_failures=result.failures,
                              require_two_signals=two_signal)
    # Advisory only: the labels are reported, never fed back into the verdict.
    verdict["c2_review"] = _c2_review(findings, all_functions, client)
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

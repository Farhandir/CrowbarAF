"""LLM katmani orkestrasyonu: bottom-up, seviye-seviye paralel ozetleme + onbellek."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from .cache import SummaryCache
from .client import LLMClient, LLMResult
from .context import (findings_for, must_include_offsets, normalize_address,
                      select_with_reasons)
from .summarize import summarize_function
from .trace import Tracer
from .traverse import scc_levels
from .types import Finding, FunctionInfo, FunctionSummary
from .verdict import apply_fail_closed
ZERO_RESULT = LLMResult(content="", prompt_tokens=0, completion_tokens=0)


@dataclass
class AnalysisResult:
    summaries: dict[str, FunctionSummary] = field(default_factory=dict)
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    calls: int = 0
    cache_hits: int = 0
    failures: list[str] = field(default_factory=list)
    per_function: dict[str, dict] = field(default_factory=dict)
    must_include: list[str] = field(default_factory=list)
    trace: Tracer | None = None

    def token_total(self) -> int:
        return self.total_prompt_tokens + self.total_completion_tokens


def analyze(
    functions: list[FunctionInfo],
    findings: list[Finding],
    client: LLMClient,
    budget_tokens: int = 6000,
    skip_library: bool = True,
    tracer: Tracer | None = None,
    total_budget_tokens: int | None = None,
    max_workers: int = 1,
    cache: SummaryCache | None = None,
    max_retries: int = 2,
    low_priority_budget: int | None = None,
    low_priority_threshold: int = 1,
    min_priority: int = 0,
) -> AnalysisResult:
    """Tum fonksiyonlari bottom-up ozetler.

    budget_tokens       : fonksiyon basina context butcesi
    total_budget_tokens : (ops.) kosu icin secim butcesi; dusuk oncelikler atlanir
    max_workers         : ayni seviyedeki bagimsiz fonksiyonlar icin paralellik
    cache               : SummaryCache (memoization)
    low_priority_budget : (ops.) esik altindaki fonksiyonlar icin kucuk butce
                          (SKIP yerine yumusak eleme)
    """
    tracer = tracer or Tracer(
        model=getattr(client, "model", ""), provider=getattr(client, "provider", ""),
        budget_tokens=budget_tokens, skip_library=skip_library,
    )

    must = must_include_offsets(functions, findings)
    must_norm = {normalize_address(x) for x in must}
    if must:
        tracer.event("must_include", offsets=sorted(must))

    if total_budget_tokens is not None:
        fns, skipped = select_with_reasons(functions, total_budget_tokens, skip_library,
                                           min_priority, must)
        for fn, reason in skipped:
            tracer.skipped(fn, reason)
    else:
        fns = []
        for f in functions:
            is_must = normalize_address(f.offset) in must_norm
            if skip_library and f.is_library and not is_must:
                tracer.skipped(f, "library")
            elif (f.priority or 0) < min_priority and not is_must:
                tracer.skipped(f, "priority")
            else:
                fns.append(f)

    by_offset = {f.offset: f for f in fns}
    result = AnalysisResult(must_include=sorted(must))

    levels = scc_levels(fns)

    for level_idx, level in enumerate(levels):
        tasks = [off for scc in level for off in scc]
        tracer.event("level", level=level_idx, tasks=len(tasks))
        snapshot = dict(result.summaries)  # ayni seviyedekiler birbirini etkilemesin

        def run_one(offset: str):
            fn = by_offset[offset]
            callee_summaries = [snapshot[c] for c in fn.callees if c in snapshot]
            if cache is not None:
                hit = cache.get(fn)
                if hit is not None:
                    return offset, hit, ZERO_RESULT, {"cached": True, "json_ok": True}, 0.0, None
            fn_budget = budget_tokens
            if low_priority_budget is not None and (fn.priority or 0) < low_priority_threshold:
                fn_budget = low_priority_budget
            if normalize_address(fn.offset) in must_norm:
                fn_budget = budget_tokens  # must-include gets the full budget
            t0 = time.monotonic()
            try:
                summary, res, stats = summarize_function(
                    client, fn, callee_summaries, findings, fn_budget, max_retries)
                summary = apply_fail_closed(summary, fn, findings)
                stats["fail_closed"] = summary.fail_closed
                return offset, summary, res, stats, time.monotonic() - t0, None
            except Exception as exc:  # noqa: BLE001
                return offset, None, None, {}, time.monotonic() - t0, f"{type(exc).__name__}: {exc}"

        if max_workers > 1 and len(tasks) > 1:
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                futures = [ex.submit(run_one, off) for off in tasks]
                outcomes = [f.result() for f in as_completed(futures)]
        else:
            outcomes = [run_one(off) for off in tasks]

        for offset, summary, res, stats, duration, error in outcomes:
            fn = by_offset[offset]
            if error or summary is None:
                result.failures.append(f"{offset}: {error}")
                result.summaries[offset] = FunctionSummary(offset=offset, summary="(analiz edilemedi)")
                tracer.event("error", offset=offset, error=(error or "")[:200])
                continue
            cached = bool(stats.get("cached"))
            result.summaries[offset] = summary
            if cached:
                result.cache_hits += 1
            else:
                result.calls += 1
                result.total_prompt_tokens += (res.prompt_tokens or 0)
                result.total_completion_tokens += (res.completion_tokens or 0)
                if cache is not None:
                    cache.put(fn, summary)
            result.per_function[offset] = {
                **stats,
                "prompt_tokens": res.prompt_tokens,
                "completion_tokens": res.completion_tokens,
                "cached": cached,
            }
            tracer.analyzed(
                fn, stats, res, summary, duration,
                children=[c.offset for c in snapshot.values() if c.offset in fn.callees],
                n_findings=len(findings_for(fn, findings)),
                cached=cached,
            )

    if cache is not None:
        cache.save()

    tracer.finalize(result)
    result.trace = tracer
    return result

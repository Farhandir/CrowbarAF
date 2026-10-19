"""LLM katmani orkestrasyonu: bottom-up ozetleme + butce muhasebesi + iz."""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from .client import LLMClient
from .context import findings_for, select_with_reasons
from .summarize import summarize_function
from .trace import Tracer
from .traverse import scc_order
from .types import Finding, FunctionInfo, FunctionSummary


@dataclass
class AnalysisResult:
    summaries: dict[str, FunctionSummary] = field(default_factory=dict)
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    calls: int = 0
    failures: list[str] = field(default_factory=list)
    per_function: dict[str, dict] = field(default_factory=dict)
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
) -> AnalysisResult:
    """Tum fonksiyonlari bottom-up ozetler.

    budget_tokens       : fonksiyon basina context butcesi
    total_budget_tokens : (ops.) tum kosu icin secim butcesi; verilirse
                          dusuk oncelikli fonksiyonlar atlanir (iz'e yazilir).
    """
    tracer = tracer or Tracer(
        model=getattr(client, "model", ""), provider=getattr(client, "provider", ""),
        budget_tokens=budget_tokens, skip_library=skip_library,
    )

    if total_budget_tokens is not None:
        fns, skipped = select_with_reasons(functions, total_budget_tokens, skip_library)
        for fn, reason in skipped:
            tracer.skipped(fn, reason)
    else:
        fns = []
        for f in functions:
            if skip_library and f.is_library:
                tracer.skipped(f, "library")
            else:
                fns.append(f)

    by_offset = {f.offset: f for f in fns}
    result = AnalysisResult()

    for scc in scc_order(fns):
        for offset in scc:
            fn = by_offset[offset]
            callee_summaries = [result.summaries[c] for c in fn.callees if c in result.summaries]
            t0 = time.monotonic()
            try:
                summary, res, stats = summarize_function(
                    client, fn, callee_summaries, findings, budget_tokens)
            except Exception as exc:  # noqa: BLE001 - akis cokmemeli
                result.failures.append(f"{offset}: {type(exc).__name__}: {exc}")
                result.summaries[offset] = FunctionSummary(offset=offset, summary="(analiz edilemedi)")
                tracer.event("error", offset=offset, error=str(exc)[:200])
                continue
            duration = time.monotonic() - t0

            result.summaries[offset] = summary
            result.calls += 1
            result.total_prompt_tokens += (res.prompt_tokens or 0)
            result.total_completion_tokens += (res.completion_tokens or 0)
            result.per_function[offset] = {
                **stats,
                "prompt_tokens": res.prompt_tokens,
                "completion_tokens": res.completion_tokens,
            }
            tracer.analyzed(
                fn, stats, res, summary, duration,
                children=[c.offset for c in callee_summaries],
                n_findings=len(findings_for(fn, findings)),
            )

    tracer.finalize(result)
    result.trace = tracer
    return result

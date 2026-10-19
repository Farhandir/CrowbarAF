"""LLM katmani orkestrasyonu: bottom-up ozetleme + butce muhasebesi."""
from __future__ import annotations

from dataclasses import dataclass, field

from .client import LLMClient
from .summarize import summarize_function
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

    def token_total(self) -> int:
        return self.total_prompt_tokens + self.total_completion_tokens


def analyze(
    functions: list[FunctionInfo],
    findings: list[Finding],
    client: LLMClient,
    budget_tokens: int = 6000,
    skip_library: bool = True,
) -> AnalysisResult:
    """Tum fonksiyonlari bottom-up ozetler.

    Butce her fonksiyon icin ayridir (per-function context budget).
    """
    fns = [f for f in functions if not (skip_library and f.is_library)]
    by_offset = {f.offset: f for f in fns}
    result = AnalysisResult()

    for scc in scc_order(fns):
        for offset in scc:
            fn = by_offset[offset]
            callee_summaries = [
                result.summaries[c] for c in fn.callees if c in result.summaries
            ]
            try:
                summary, res, stats = summarize_function(
                    client, fn, callee_summaries, findings, budget_tokens)
            except Exception as exc:  # noqa: BLE001 - akis cokmemeli
                result.failures.append(f"{offset}: {type(exc).__name__}: {exc}")
                result.summaries[offset] = FunctionSummary(offset=offset, summary="(analiz edilemedi)")
                continue

            result.summaries[offset] = summary
            result.calls += 1
            result.total_prompt_tokens += (res.prompt_tokens or 0)
            result.total_completion_tokens += (res.completion_tokens or 0)
            result.per_function[offset] = {
                **stats,
                "prompt_tokens": res.prompt_tokens,
                "completion_tokens": res.completion_tokens,
            }

    return result

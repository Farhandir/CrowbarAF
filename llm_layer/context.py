"""Budget-aware context construction.

Goal (decision-preserving compression): fit the function code + callee summaries +
findings into a fixed token budget while **preserving the information that changes
the decision**.
"""
from __future__ import annotations

from .tokens import estimate_tokens, truncate_to_tokens
from .types import Finding, FunctionInfo, FunctionSummary


def select_with_reasons(
    functions: list[FunctionInfo], budget_tokens: int, skip_library: bool = True,
    min_priority: int = 0,
) -> tuple[list[FunctionInfo], list[tuple[FunctionInfo, str]]]:
    """Select by budget; return skipped functions **with their reason**.

    min_priority: functions below this threshold are never analyzed ("priority").
    """
    remaining = budget_tokens
    selected: list[FunctionInfo] = []
    skipped: list[tuple[FunctionInfo, str]] = []
    ranked = sorted(functions, key=lambda f: (-f.priority, estimate_tokens(f.c_code)))
    for fn in ranked:
        if skip_library and fn.is_library:
            skipped.append((fn, "library"))
            continue
        if (fn.priority or 0) < min_priority:
            skipped.append((fn, "priority"))
            continue
        cost = estimate_tokens(fn.c_code) + 32  # header/overhead
        if cost > remaining:
            skipped.append((fn, "budget"))
            continue
        selected.append(fn)
        remaining -= cost
    return selected, skipped


def select_functions(
    functions: list[FunctionInfo], budget_tokens: int, skip_library: bool = True,
    min_priority: int = 0,
) -> list[FunctionInfo]:
    """Select functions by budget (highest priority first, then smallest)."""
    return select_with_reasons(functions, budget_tokens, skip_library, min_priority)[0]


def findings_for(fn: FunctionInfo, findings: list[Finding]) -> list[Finding]:
    """Findings that match this function's address (or are address-less/global)."""
    out = []
    for f in findings:
        if f.address is None or f.address == fn.offset:
            out.append(f)
    return out


def build_function_context(
    fn: FunctionInfo,
    callee_summaries: list[FunctionSummary],
    findings: list[Finding],
    budget_tokens: int,
) -> tuple[str, dict]:
    """Fit the context for one function into the token budget.

    Returns: (context_text, stats)
    """
    header = [
        f"Function: {fn.name or '?'} @ {fn.offset}",
        f"Priority: {fn.priority}  Size: {fn.size or len(fn.c_code)}",
    ]
    if fn.is_library:
        header.append("Note: library/thunk function (low priority).")
    if fn.decompile_warnings:
        header.append("Decompile warnings: " + "; ".join(fn.decompile_warnings[:5]))

    # 1) findings (short)
    ev_lines = [f"- [{f.source}/{f.kind}] {f.value}" + (f" @ {f.address}" if f.address else "")
                for f in findings[:20]]
    ev_block = "\n".join(ev_lines)

    # 2) callee summaries (notes, not code)
    child_lines = [f"- {s.note()}" for s in callee_summaries[:40]]
    child_block = "\n".join(child_lines)

    fixed_overhead = (
        estimate_tokens("\n".join(header))
        + estimate_tokens(ev_block)
        + estimate_tokens(child_block)
        + 120  # template/prompt allowance
    )
    code_budget = max(64, budget_tokens - fixed_overhead)
    code = truncate_to_tokens(fn.c_code, code_budget)

    text = "\n".join(header)
    if ev_block:
        text += "\n\nFINDINGS (deterministic tools):\n" + ev_block
    if child_block:
        text += "\n\nCALLEE SUMMARIES:\n" + child_block
    text += "\n\nCODE:\n```c\n" + code + "\n```"

    stats = {
        "estimated_tokens": estimate_tokens(text),
        "code_truncated": len(code) < len(fn.c_code),
        "budget": budget_tokens,
    }
    return text, stats

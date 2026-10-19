"""Butce-farkinda baglam insasi.

Amac (decision-preserving compression): fonksiyon kodunu + cocuk ozetlerini +
kanitlari, **karari degistiren bilgiyi koruyarak** sabit bir token butcesine
sigdiranak LLM'e vermek.
"""
from __future__ import annotations

from .tokens import estimate_tokens, truncate_to_tokens
from .types import Finding, FunctionInfo, FunctionSummary


def select_functions(functions: list[FunctionInfo], budget_tokens: int) -> list[FunctionInfo]:
    """Butceye gore fonksiyon secer: yuksek oncelik once, esitlikte kucuk once."""
    remaining = budget_tokens
    selected: list[FunctionInfo] = []
    ranked = sorted(functions, key=lambda f: (-f.priority, estimate_tokens(f.c_code)))
    for fn in ranked:
        cost = estimate_tokens(fn.c_code) + 32  # baslik/overhead
        if cost <= remaining:
            selected.append(fn)
            remaining -= cost
    return selected


def findings_for(fn: FunctionInfo, findings: list[Finding]) -> list[Finding]:
    """Bu fonksiyonun adresiyle eslesen (veya adressiz/genel) bulgular."""
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
    """LLM'e verilecek fonksiyon baglamini butceye sigdirir.

    Donus: (context_text, olcum_dict)
    """
    header = [
        f"Fonksiyon: {fn.name or '?'} @ {fn.offset}",
        f"Oncelik: {fn.priority}  Boyut: {fn.size or len(fn.c_code)}",
    ]
    if fn.is_library:
        header.append("Not: kutuphane/thunk fonksiyonu (dusuk oncelik).")
    if fn.decompile_warnings:
        header.append("Decompile uyarilari: " + "; ".join(fn.decompile_warnings[:5]))

    # 1) kanitlar (kisa)
    ev_lines = [f"- [{f.source}/{f.kind}] {f.value}" + (f" @ {f.address}" if f.address else "")
                for f in findings[:20]]
    ev_block = "\n".join(ev_lines)

    # 2) cocuk ozetleri (kod degil, not)
    child_lines = [f"- {s.note()}" for s in callee_summaries[:40]]
    child_block = "\n".join(child_lines)

    fixed_overhead = (
        estimate_tokens("\n".join(header))
        + estimate_tokens(ev_block)
        + estimate_tokens(child_block)
        + 120  # sablon/prompt payi
    )
    code_budget = max(64, budget_tokens - fixed_overhead)
    code = truncate_to_tokens(fn.c_code, code_budget)

    text = "\n".join(header)
    if ev_block:
        text += "\n\nKANITLAR (deterministik araclar):\n" + ev_block
    if child_block:
        text += "\n\nCAGIRDIGI FONKSIYONLARIN OZETLERI:\n" + child_block
    text += "\n\nKOD:\n```c\n" + code + "\n```"

    stats = {
        "estimated_tokens": estimate_tokens(text),
        "code_truncated": len(code) < len(fn.c_code),
        "budget": budget_tokens,
    }
    return text, stats

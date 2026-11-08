#!/usr/bin/env python3
"""Cost-only comparison: naive full-context prompt vs actual Crowbar usage.

This does not call an LLM. It estimates the input tokens for a single naive
prompt containing every decompiled function and finding, and compares that to
the actual prompt tokens recorded in a Crowbar trace.

Usage:
    python experiments/cost_compare.py state.json [state2.json ...]
    python experiments/cost_compare.py --trace runs/llm_trace_x.json state.json
    python experiments/cost_compare.py --json states/*.llm.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from llm_layer.tokens import estimate_tokens

NAIVE_SYSTEM = (
    "You are a malware analyst. Review the following decompiled functions and "
    "deterministic findings. Decide whether the sample is malicious, benign, "
    "or unknown. Explain the evidence."
)


def _trace_path(state: dict[str, Any], explicit: str | None = None) -> str | None:
    if explicit:
        return explicit
    match = re.search(r"Trace:\s*(\S+\.json)", str(state.get("intent_analysis") or ""))
    return match.group(1) if match else None


def _load_trace(path: str | None) -> dict[str, Any] | None:
    if not path or not os.path.isfile(path):
        return None
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return None


def naive_prompt(state: dict[str, Any]) -> str:
    functions = [f for f in (state.get("source_code") or [])
                 if str(f.get("c_code") or "").strip()]
    findings = state.get("findings") or []
    parts = [NAIVE_SYSTEM, "", f"FUNCTIONS ({len(functions)}):"]
    for f in functions:
        parts.append(f"\n### {f.get('name') or '?'} @ {f.get('offset') or '?'}")
        parts.append(str(f.get("c_code") or ""))
    parts.append(f"\nFINDINGS ({len(findings)}):")
    for f in findings:
        value = str(f.get("value") or "")[:500]
        parts.append(f"- [{f.get('source')}/{f.get('kind')}] {value}")
    return "\n".join(parts)


def measure(state: dict[str, Any], trace: dict[str, Any] | None = None,
            context_tokens: int = 131072) -> dict[str, Any]:
    functions = [f for f in (state.get("source_code") or [])
                 if str(f.get("c_code") or "").strip()]
    prompt = naive_prompt(state)
    naive_tokens = estimate_tokens(prompt)
    totals = (trace or {}).get("totals") or {}
    crowbar_prompt = int(totals.get("prompt_tokens") or 0)
    crowbar_completion = int(totals.get("completion_tokens") or 0)
    crowbar_total = int(totals.get("tokens_total") or 0)
    savings = None
    if naive_tokens and crowbar_prompt:
        savings = 1.0 - (crowbar_prompt / naive_tokens)
    verdict = state.get("verdict") or {}
    return {
        "sample_sha256": str((state.get("sample") or {}).get("sha256") or ""),
        "file_type": str((state.get("sample") or {}).get("file_type") or ""),
        "arch": str((state.get("sample") or {}).get("arch") or ""),
        "functions": len(functions),
        "code_chars": sum(len(str(f.get("c_code") or "")) for f in functions),
        "findings": len(state.get("findings") or []),
        "naive_prompt_tokens_est": naive_tokens,
        "naive_fits_context": naive_tokens <= context_tokens,
        "context_tokens": context_tokens,
        "crowbar_prompt_tokens": crowbar_prompt,
        "crowbar_completion_tokens": crowbar_completion,
        "crowbar_total_tokens": crowbar_total,
        "prompt_token_savings": round(savings, 3) if savings is not None else None,
        "verdict": verdict.get("verdict"),
        "coverage": (verdict.get("coverage") or {}).get("ratio"),
        "trace": (trace or {}).get("run"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare naive input cost with Crowbar trace cost")
    parser.add_argument("states", nargs="+", help="Crowbar state JSON (preferably .llm.json)")
    parser.add_argument("--trace", help="explicit trace JSON for a single state")
    parser.add_argument("--context", type=int, default=131072, help="context limit to test")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    rows = []
    for path in args.states:
        state = json.loads(Path(path).read_text(encoding="utf-8"))
        trace = _load_trace(_trace_path(state, args.trace if len(args.states) == 1 else None))
        row = measure(state, trace, args.context)
        row["state"] = path
        rows.append(row)

    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 0

    print(f"{'sample':40} {'funcs':>5} {'naive_tok':>10} {'crowbar_tok':>11} "
          f"{'saving':>7} {'fits':>5} {'verdict':>12}")
    for row in rows:
        name = Path(row["state"]).name[:40]
        saving = row["prompt_token_savings"]
        saving_text = f"{saving:.1%}" if saving is not None else "-"
        print(f"{name:40} {row['functions']:5} {row['naive_prompt_tokens_est']:10} "
              f"{row['crowbar_prompt_tokens']:11} {saving_text:>7} "
              f"{str(row['naive_fits_context']):>5} {str(row['verdict']):>12}")
    print("\nnaive_fits_context is a feasibility flag, not an accuracy result.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

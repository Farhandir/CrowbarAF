#!/usr/bin/env python3
"""LLM analiz izini (trace JSON) insan-okunur rapora cevirir.

Kullanim:
    python experiments/trace_report.py runs/llm_trace_XXXX.json
"""
from __future__ import annotations

import json
import sys


def main() -> None:
    if len(sys.argv) < 2:
        print("kullanim: trace_report.py <trace.json>")
        return
    d = json.load(open(sys.argv[1], encoding="utf-8"))
    run, t = d["run"], d["totals"]

    print("=== LLM ANALIZ IZI ===")
    print(f"model: {run['model']} ({run['provider']})  |  butce/fonk: {run['budget_tokens']}")
    print(f"baslangic: {run['started']}  bitis: {run['finished']}")
    print()
    print(f"fonksiyon : {t['functions_total']} | analiz: {t['functions_analyzed']} "
          f"| atlandi: {t['functions_skipped']} "
          f"(library={t['skipped_library']}, budget={t['skipped_budget']})")
    print(f"kapsama   : {t['coverage']} | cagri: {t['calls']} | token: {t['tokens_total']} "
          f"(prompt={t['prompt_tokens']}, completion={t['completion_tokens']})")
    print(f"iddialar : dogrulanan={t['verified_claims']} "
          f"dogrulanamayan={t['unverified_claims']} hata={t['failures']}")
    print()
    print(f"{'offset':<14}{'isim':<24}{'pri':>4}{'durum':>9}{'token':>7}{'sup':>5}  ozet")
    print("-" * 112)
    for f in d["functions"]:
        if f["status"] == "analyzed":
            print(f"{f['offset']:<14}{(f['name'] or '')[:23]:<24}{f['priority']:>4}{'analiz':>9}"
                  f"{str(f.get('prompt_tokens') or '-'):>7}"
                  f"{('E' if f.get('suspicious') else '-'):>5}  {(f.get('summary') or '')[:42]}")
        else:
            print(f"{f['offset']:<14}{(f['name'] or '')[:23]:<24}{f['priority']:>4}"
                  f"{'atlandi':>9}{'-':>7}{'-':>5}  ({f.get('skip_reason')})")

    print("\n=== Dogrulanamayan iddialar (sari uyari) ===")
    n = 0
    for f in d["functions"]:
        for c in f.get("claims", []):
            if c["status"] == "unverified":
                n += 1
                print(f"- {f['offset']} {f['name']}: {c['text'][:75]} | kanit: {c['evidence'][:45]}")
    if not n:
        print("(yok)")


if __name__ == "__main__":
    main()

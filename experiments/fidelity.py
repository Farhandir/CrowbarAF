#!/usr/bin/env python3
"""Faz 1 — fidelity harness: butce x strateji.

Soru: "O ncelikli + temiz kanit" stratejisi, kucuk context butcesinde
tam-context (oracle) kararina yaklasiyor mu?

Stratejiler:
  full        : cok buyuk fonksiyon-butcesi, tum fonksiyonlar, kanit var  (ORACLE)
  truncated   : kucuk fonksiyon-butcesi, tum fonksiyonlar, kanit yok
  priority    : kucuk butce + toplam secim butcesi (oncelikli), kanit yok
  priority_ev : priority + deterministik kanit

Metrikler: kapsama, oracle ile karar uyumu (fidelity), token, hata.

Kullanim:
    python experiments/fidelity.py --model qwen8:latest
    python experiments/fidelity.py --model qwen8:latest --functions ghidra_out.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from llm_layer import Finding, FunctionInfo, LLMClient, analyze  # noqa: E402

STRATEGIES = {
    "full":             dict(budget=10 ** 6, total=None, use_findings=True,  low_budget=None),
    "truncated":        dict(budget=1500,    total=None, use_findings=False, low_budget=None),
    "priority":         dict(budget=1500,    total=4000, use_findings=False, low_budget=None),
    "priority_ev":      dict(budget=1500,    total=4000, use_findings=True,  low_budget=None),
    "priority_soft":    dict(budget=1500,    total=None, use_findings=False, low_budget=400),
    "priority_soft_ev": dict(budget=1500,    total=None, use_findings=True,  low_budget=400),
}

def _pad(n: int) -> str:
    return "".join(f"  s[{i}] = (char)(s[{i}] ^ 0x5a);\n" for i in range(n))


BIG_PAYLOAD = "int payload(char *s,int n){\n" + _pad(350) + "  return n;\n}"
BIG_NOISE = "int noise(char *s,int n){\n" + _pad(350) + "  return 0;\n}"

BUILTIN = [
    {"offset": "0x401000", "name": "payload", "priority": 5, "c_code": BIG_PAYLOAD},
    {"offset": "0x4010a0", "name": "decode", "priority": 5,
     "c_code": "void decode(char *b,int n,unsigned char k){for(int i=0;i<n;i++)b[i]^=k;}"},
    {"offset": "0x4010c0", "name": "checksum", "priority": 3,
     "c_code": "int checksum(char*s,int n){unsigned h=0;for(int i=0;i<n;i++)h=h*31+s[i];return h;}"},
    {"offset": "0x4010e0", "name": "wrapper", "priority": 4, "callees": ["0x4010a0", "0x4010c0"],
     "c_code": "int wrapper(char*s,int n){decode(s,n,0x5a);return checksum(s,n);}"},
    {"offset": "0x402000", "name": "noise", "priority": 0, "c_code": BIG_NOISE},
    {"offset": "0x401300", "name": "add", "priority": 0,
     "c_code": "int add(int a,int b){return a+b;}"},
]


def load_functions(path: str | None) -> list[FunctionInfo]:
    items = BUILTIN
    if path:
        with open(path, encoding="utf-8") as fh:
            items = json.load(fh)
    return [FunctionInfo(
        offset=it.get("offset", ""), name=it.get("name", ""), c_code=it.get("c_code", ""),
        priority=it.get("priority", 0), size=it.get("size", 0),
        is_library=bool(it.get("is_library", False)),
        callees=list(it.get("callees", []) or []),
    ) for it in items]


def decisions(result) -> dict[str, bool]:
    return {o: s.suspicious for o, s in result.summaries.items() if s.suspicious is not None}


def fidelity(oracle: dict[str, bool], variant: dict[str, bool]) -> tuple[float | None, int]:
    common = set(oracle) & set(variant)
    if not common:
        return None, 0
    agree = sum(1 for o in common if oracle[o] == variant[o])
    return agree / len(common), len(common)


def run_strategy(name: str, cfg: dict, functions, findings, client):
    use_findings = cfg["use_findings"]
    res = analyze(
        functions, findings if use_findings else [], client,
        budget_tokens=cfg["budget"], total_budget_tokens=cfg["total"],
        low_priority_budget=cfg.get("low_budget"),
    )
    return res


def main() -> None:
    ap = argparse.ArgumentParser(description="Fidelity harness (butce x strateji)")
    ap.add_argument("--model", default=os.environ.get("CROWBAR_LLM_MODEL", "qwen8:latest"))
    ap.add_argument("--provider", default=os.environ.get("CROWBAR_LLM_PROVIDER", "ollama"))
    ap.add_argument("--base-url", default=os.environ.get("CROWBAR_LLM_BASE_URL", "http://localhost:11434"))
    ap.add_argument("--functions", help="ExportC formatinda fonksiyon JSON'u")
    ap.add_argument("--out", help="sonuc JSON'u")
    args = ap.parse_args()

    functions = load_functions(args.functions)
    findings = [Finding(source="capa", kind="capability", value="string decoding", address="0x401000")]

    client = LLMClient(provider=args.provider, model=args.model, base_url=args.base_url,
                       num_ctx=32768, num_predict=900)

    # Oracle once
    oracle_res = run_strategy("full", STRATEGIES["full"], functions, findings, client)
    oracle = decisions(oracle_res)
    print(f"ORACLE ({args.model}): {len(oracle)} karar, token={oracle_res.token_total()}")
    print("  kararlar:", {o: ("S" if v else "n") for o, v in oracle.items()})
    n_susp = sum(1 for v in oracle.values() if v)
    print(f"  supheli={n_susp}/{len(oracle)}")

    rows = []
    suspicious_oracle = {o for o, v in oracle.items() if v}
    print(f"\n{'strateji':<13}{'fonk':>6}{'kapsama':>9}{'fidelity':>10}{'recall':>8}"
          f"{'token':>8}{'hata':>6}")
    print("-" * 66)
    for name, cfg in STRATEGIES.items():
        if name == "full":
            res = oracle_res
        else:
            res = run_strategy(name, cfg, functions, findings, client)
        dec = decisions(res)
        fid, common = fidelity(oracle, dec)
        coverage = len(dec) / len(oracle) if oracle else 0.0
        caught = {o for o, v in dec.items() if v}
        recall = (len(suspicious_oracle & caught) / len(suspicious_oracle)) if suspicious_oracle else None
        missed = sorted(suspicious_oracle - caught)
        print(f"{name:<13}{len(dec):>6}{coverage:>9.2f}"
              f"{(f'{fid:.2f}' if fid is not None else '-'):>10}"
              f"{(f'{recall:.2f}' if recall is not None else '-'):>8}"
              f"{res.token_total():>8}{len(res.failures):>6}")
        if missed:
            print(f"   kacan supheli: {missed}")
        rows.append({
            "strategy": name, "decisions": len(dec), "coverage": round(coverage, 3),
            "fidelity": (round(fid, 3) if fid is not None else None),
            "recall": (round(recall, 3) if recall is not None else None),
            "missed_suspicious": missed,
            "common": common, "tokens": res.token_total(),
            "cache_hits": res.cache_hits, "failures": len(res.failures),
            "per_function": {o: ("suspicious" if v else "benign") for o, v in dec.items()},
        })

    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump({"model": args.model, "oracle_decisions": len(oracle),
                       "oracle_per_function": {o: ("suspicious" if v else "benign") for o, v in oracle.items()},
                       "rows": rows}, fh, ensure_ascii=False, indent=2)
        print(f"\nyazildi: {args.out}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Faz 1 — fidelity harness: butce x strateji (n kosu + oracle kararliligi).

Soru: "O ncelikli + temiz kanit" stratejisi, kucuk context butcesinde
tam-context (oracle) kararina yaklasiyor mu?

Ek: n kosu ile (a) oracle'in kendi tutarliligi (stability), (b) stratejilerin
fidelity/recall varyansi olculur.

Kullanim:
    python experiments/fidelity.py --model qwen8:latest --runs 5 --workers 2
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from llm_layer import Finding, FunctionInfo, LLMClient, analyze  # noqa: E402

STRATEGIES = {
    "full":                   dict(budget=10 ** 6, total=None, use_findings=True,  low_budget=None, min_priority=0),
    "truncated":              dict(budget=1500,    total=None, use_findings=False, low_budget=None, min_priority=0),
    "priority":               dict(budget=1500,    total=4000, use_findings=False, low_budget=None, min_priority=0),
    "priority_ev":            dict(budget=1500,    total=4000, use_findings=True,  low_budget=None, min_priority=0),
    "priority_soft":          dict(budget=1500,    total=None, use_findings=False, low_budget=400,  min_priority=0),
    "priority_soft_ev":       dict(budget=1500,    total=None, use_findings=True,  low_budget=400,  min_priority=0),
    "priority_threshold":     dict(budget=1500,    total=None, use_findings=False, low_budget=None, min_priority=1),
    "priority_threshold_ev":  dict(budget=1500,    total=None, use_findings=True,  low_budget=None, min_priority=1),
}


def _pad(n: int, key: str = "0x5a") -> str:
    return "".join(f"  s[{i}] = (char)(s[{i}] ^ {key});\n" for i in range(n))


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


def majority(decs: list[dict[str, bool]]) -> dict[str, bool]:
    offsets = set().union(*decs) if decs else set()
    out = {}
    for o in offsets:
        vals = [d[o] for d in decs if o in d]
        if vals:
            out[o] = sum(vals) * 2 >= len(vals)
    return out


def prf(dec: dict[str, bool], gt: set[str]) -> tuple[int, int, int, float, float]:
    """Ground truth'a gore precision/recall (supheli = pozitif)."""
    susp = {o for o, v in dec.items() if v}
    tp = len(susp & gt)
    fp = len(susp - gt)
    fn = len(gt - susp)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    return tp, fp, fn, precision, recall


def stability(decs: list[dict[str, bool]]) -> float:
    """Fonksiyon basina kosulararasi tutarlilik (1.0 = hep ayni, 0.5 = yazi-tura)."""
    scores = []
    for o in set().union(*decs) if decs else set():
        vals = [d[o] for d in decs if o in d]
        if not vals:
            continue
        p = sum(vals) / len(vals)
        scores.append(max(p, 1 - p))
    return sum(scores) / len(scores) if scores else 0.0


def run_strategy(cfg: dict, functions, findings, client, workers: int = 1):
    return analyze(
        functions, findings if cfg["use_findings"] else [], client,
        budget_tokens=cfg["budget"], total_budget_tokens=cfg["total"],
        low_priority_budget=cfg.get("low_budget"), max_workers=workers,
        min_priority=cfg.get("min_priority", 0),
    )


def _mean_std(xs: list[float]) -> str:
    xs = [x for x in xs if x is not None]
    if not xs:
        return "-"
    if len(xs) == 1:
        return f"{xs[0]:.2f}"
    return f"{statistics.mean(xs):.2f}±{statistics.pstdev(xs):.2f}"


def main() -> None:
    ap = argparse.ArgumentParser(description="Fidelity harness (n kosu + oracle stability)")
    ap.add_argument("--model", default=os.environ.get("CROWBAR_LLM_MODEL", "qwen8:latest"))
    ap.add_argument("--provider", default=os.environ.get("CROWBAR_LLM_PROVIDER", "ollama"))
    ap.add_argument("--base-url", default=os.environ.get("CROWBAR_LLM_BASE_URL", "http://localhost:11434"))
    ap.add_argument("--functions", help="ExportC formatinda fonksiyon JSON'u")
    ap.add_argument("--out", help="sonuc JSON'u")
    ap.add_argument("--runs", type=int, default=1, help="her strateji icin kosu sayisi")
    ap.add_argument("--workers", type=int, default=1, help="paralel istek")
    ap.add_argument("--strategies", help="virgullu alt kume (or. truncated,priority_soft)")
    ap.add_argument("--ground-truth", help="GT supheli offset listesi (JSON dizi)")
    ap.add_argument("--budget-sweep", help="virgullu butce listesi (or. 1500,800,400,200)")
    ap.add_argument("--sweep-strategy", default="priority_soft", help="supurulecek strateji")
    ap.add_argument("--budget", type=int)
    ap.add_argument("--total", type=int)
    ap.add_argument("--low-budget", type=int)
    args = ap.parse_args()

    for _name, _cfg in STRATEGIES.items():
        if _name == "full":
            continue
        if args.budget is not None:
            _cfg["budget"] = args.budget
        if args.total is not None and _cfg["total"] is not None:
            _cfg["total"] = args.total
        if args.low_budget is not None:
            _cfg["low_budget"] = args.low_budget

    functions = load_functions(args.functions)
    target = next((f.offset for f in functions if f.priority >= 5), functions[0].offset if functions else "")
    findings = [Finding(source="capa", kind="capability", value="string decoding", address=target)]

    client = LLMClient(provider=args.provider, model=args.model, base_url=args.base_url,
                       num_ctx=32768, num_predict=900)

    gt = None
    if args.ground_truth:
        with open(args.ground_truth, encoding="utf-8") as fh:
            gt = set(json.load(fh))

    # --- oracle: n kosu ---
    oracle_runs = [run_strategy(STRATEGIES["full"], functions, findings, client, args.workers)
                   for _ in range(args.runs)]
    oracle_decs = [decisions(r) for r in oracle_runs]
    oracle = majority(oracle_decs)
    oracle_stab = stability(oracle_decs)
    oracle_tokens = [r.token_total() for r in oracle_runs]
    n_susp = sum(1 for v in oracle.values() if v)
    print(f"ORACLE ({args.model}, runs={args.runs}): {len(oracle)} fonksiyon, "
          f"supheli={n_susp}, stability={oracle_stab:.2f}, token={_mean_std(oracle_tokens)}")

    names = [n for n in (args.strategies.split(",") if args.strategies else STRATEGIES)
             if n != "full"]
    suspicious_oracle = {o for o, v in oracle.items() if v}

    if gt is not None:
        tp, fp, fn, p, r = prf(oracle, gt)
        print(f"ORACLE GT: precision={p:.2f} recall={r:.2f}  (tp={tp} fp={fp} fn={fn})")

    # --- butce supurmesi ---
    if args.budget_sweep:
        sweep = [int(x) for x in args.budget_sweep.split(",")]
        avg_oracle_tokens = sum(oracle_tokens) / len(oracle_tokens) if oracle_tokens else 0
        print(f"\nBUDGET SWEEP ({args.sweep_strategy})")
        print(f"{'butce':>8}{'fonk':>6}{'GT-P':>8}{'GT-R':>8}{'token':>10}{'tasarruf':>10}")
        print("-" * 52)
        sweep_rows = []
        for b in sweep:
            cfg = dict(STRATEGIES[args.sweep_strategy])
            cfg["budget"] = b
            if cfg.get("low_budget") is not None:
                cfg["low_budget"] = max(100, b // 4)
            res = run_strategy(cfg, functions, findings, client, args.workers)
            dec = decisions(res)
            p = r = 0.0
            if gt is not None:
                _, _, _, p, r = prf(dec, gt)
            tokens = res.token_total()
            saving = (1 - tokens / avg_oracle_tokens) if avg_oracle_tokens else 0.0
            print(f"{b:>8}{len(dec):>6}{p:>8.2f}{r:>8.2f}{tokens:>10}{saving:>9.0%}")
            sweep_rows.append({"budget": b, "functions": len(dec), "gt_precision": round(p, 3),
                               "gt_recall": round(r, 3), "tokens": tokens,
                               "saving": round(saving, 3)})
        if args.out:
            os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
            with open(args.out, "w", encoding="utf-8") as fh:
                json.dump({"model": args.model, "strategy": args.sweep_strategy,
                           "oracle_tokens": avg_oracle_tokens,
                           "ground_truth": sorted(gt) if gt is not None else None,
                           "oracle_gt": (lambda t: {"precision": t[3], "recall": t[4], "tp": t[0], "fp": t[1], "fn": t[2]})(prf(oracle, gt)) if gt is not None else None,
                           "sweep": sweep_rows}, fh, ensure_ascii=False, indent=2)
            print(f"\nyazildi: {args.out}")
        return

    rows = []
    print(f"\n{'strateji':<18}{'fonk':>6}{'kapsama':>11}{'fidelity':>16}"
          f"{'GT-P':>9}{'GT-R':>9}{'token':>16}")
    print("-" * 88)
    for name in names:
        cfg = STRATEGIES[name]
        runs = [run_strategy(cfg, functions, findings, client, args.workers) for _ in range(args.runs)]
        decs = [decisions(r) for r in runs]
        fids, recalls, precs_gt, recalls_gt, covs = [], [], [], [], []
        for dec in decs:
            fid, _ = fidelity(oracle, dec)
            if fid is not None:
                fids.append(fid)
            caught = {o for o, v in dec.items() if v}
            if suspicious_oracle:
                recalls.append(len(suspicious_oracle & caught) / len(suspicious_oracle))
            if gt is not None:
                _, _, _, p, r = prf(dec, gt)
                precs_gt.append(p)
                recalls_gt.append(r)
            covs.append(len(dec) / len(oracle) if oracle else 0.0)
        tokens = [r.token_total() for r in runs]
        print(f"{name:<18}{len(decs[-1]):>6}{_mean_std(covs):>11}"
              f"{_mean_std(fids):>16}{_mean_std(precs_gt):>9}{_mean_std(recalls_gt):>9}"
              f"{_mean_std(tokens):>16}")
        rows.append({
            "strategy": name, "runs": args.runs,
            "coverage": _mean_std(covs), "fidelity": _mean_std(fids),
            "oracle_recall": _mean_std(recalls),
            "gt_precision": _mean_std(precs_gt), "gt_recall": _mean_std(recalls_gt),
            "tokens": _mean_std(tokens),
            "decisions_last_run": {o: ("suspicious" if v else "benign") for o, v in decs[-1].items()},
        })

    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump({
                "model": args.model, "runs": args.runs, "workers": args.workers,
                "oracle_stability": round(oracle_stab, 3),
                "oracle_tokens": _mean_std(oracle_tokens),
                "oracle_per_function": {o: ("suspicious" if v else "benign") for o, v in oracle.items()},
                "ground_truth": sorted(gt) if gt is not None else None,
                "oracle_gt": (lambda t: {"precision": t[3], "recall": t[4], "tp": t[0], "fp": t[1], "fn": t[2]})(prf(oracle, gt)) if gt is not None else None,
                "rows": rows,
            }, fh, ensure_ascii=False, indent=2)
        print(f"\nyazildi: {args.out}")


if __name__ == "__main__":
    main()

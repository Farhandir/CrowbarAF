"""Tool-first report: deterministic tool output + (optional) AI commentary.

Principles:
  * **Tool output** (DIE/YARA/capa/FLOSS/import/entropy/Ghidra) is the main content.
  * **AI commentary** is separate and marked ("may be unverified").
  * If there is no evidence, the verdict is **"unknown"** — never "clean".

Usage:
    python report.py <state.json> [--format md|html|json] [--out reports/]
    python report.py --db <sha256> [--format md] [--out reports/]
"""
from __future__ import annotations

import argparse
import datetime as _dt
import html
import json
import os
import re
import sys

FLOSS_CAP = 60
IMPORT_CAP = 80
FUNC_CAP = 40

CLAIM_GROUPS = [
    ("verified_claim", "Verified claims (function-local evidence)"),
    ("verified_observation", "Observations (code-quote based)"),
    ("file_level", "File-level evidence (function attribution unclear)"),
    ("unverified", "Unverified claims (not sure)"),
]


def _by_source(findings: list[dict], source: str) -> list[dict]:
    return [f for f in findings if f.get("source") == source]


def _interesting(fn: dict) -> bool:
    return bool(fn.get("capa_hits")) or (fn.get("priority") or 0) >= 4


def build(state: dict, trace: dict | None = None) -> dict:
    sample = state.get("sample", {}) or {}
    findings = state.get("findings", []) or []
    caps = state.get("capabilities", {}) or {}
    functions = state.get("source_code", []) or []
    strings = state.get("extracted_strings", []) or []

    yara = [{"rule": f.get("value"), "address": f.get("address")} for f in _by_source(findings, "yara")]
    imports = [f.get("value") for f in _by_source(findings, "import")]
    combos = [f.get("value") for f in _by_source(findings, "import_combo")]
    entropy = [{"value": f.get("value"), "kind": f.get("kind")} for f in
               (_by_source(findings, "entropy") + _by_source(findings, "pefile_entropy")
                + _by_source(findings, "elf_entropy"))]
    imphash = next((f.get("value") for f in _by_source(findings, "imphash")), "")
    pe_metadata = [{"kind": f.get("kind"), "value": f.get("value")} for f in _by_source(findings, "pe_metadata")]
    floss_findings = _by_source(findings, "floss")

    ghidra_funcs = [f for f in functions if (f.get("c_code") or "").strip()]
    edges = sum(len(f.get("callees", []) or []) for f in functions)
    warnings = sum(len(f.get("decompile_warnings", []) or []) for f in functions)
    prioritized = sorted(functions, key=lambda x: (-(x.get("priority") or 0), x.get("offset") or ""))

    deterministic = bool(yara or caps.get("matched_rules") or combos or imports or entropy)
    if deterministic:
        level, note = "high", "Deterministic tool(s) produced findings."
    elif floss_findings or strings:
        level, note = "medium", "Only string/IoC-level output is available."
    else:
        level, note = "unknown", ("No tool output. This file is NOT 'clean'; it is "
                                  "'unknown' and requires manual review.")

    v4 = state.get("verdict") or {}
    state_v = None
    if v4:
        state_v = v4.get("verdict", "unknown")
        level = {"malicious": "high", "needs_review": "medium",
                 "unknown": "unknown", "no_evidence": "unknown"}.get(state_v, "unknown")
        note = "; ".join(v4.get("reasons") or v4.get("unknown_reasons") or [])
        deterministic = bool(v4.get("critical_findings"))

    ai = None
    if trace:
        claims = []
        for fn in trace.get("functions", []):
            for c in fn.get("claims", []):
                claims.append({"offset": fn.get("offset"), "name": fn.get("name"), **c})
        ai = {"claims": claims, "functions_analyzed": trace.get("totals", {}).get("functions_analyzed", 0)}

    return {
        "generated_at": _dt.datetime.now().isoformat(timespec="seconds"),
        "identity": {
            "sha256": sample.get("sha256", ""), "file_type": sample.get("file_type", "unknown"),
            "arch": sample.get("arch", "unknown"), "packer": sample.get("packer", "unknown"),
            "route": sample.get("route", "unknown"),
        },
        "verdict": {
            "level": level, "note": note,
            "state": state_v,
            "has_deterministic_evidence": deterministic,
            "coverage": (v4.get("coverage") or {}),
            "unknown_reasons": (v4.get("unknown_reasons") or []),
            "next_actions": (v4.get("next_actions") or []),
        },
        "tools": {
            "die": {"file_type": sample.get("file_type", "unknown"), "arch": sample.get("arch", "unknown"),
                    "packer": sample.get("packer", "unknown")},
            "yara": yara,
            "capa": {
                "matched_rules": caps.get("matched_rules", []),
                "mitre_attack": caps.get("mitre_attack", []),
                "malware_behavior": caps.get("malware_behavior", []),
            },
            "floss": {"strings": strings[:FLOSS_CAP], "string_count": len(strings),
                      "ioc_findings": [f.get("value") for f in floss_findings]},
            "imports": {"list": imports[:IMPORT_CAP], "import_count": len(imports), "combos": combos,
                        "imphash": imphash},
            "entropy": entropy,
            "pe_metadata": pe_metadata,
            "ghidra": {
                "function_count": len(functions), "decompiled": len(ghidra_funcs),
                "call_edges": edges, "decompile_warnings": warnings,
                "prioritized": [
                    {"offset": f.get("offset"), "name": f.get("name"), "priority": f.get("priority", 0),
                     "size": f.get("size", 0), "interesting": _interesting(f),
                     "capa_hits": f.get("capa_hits", []), "callees": f.get("callees", [])}
                    for f in prioritized[:FUNC_CAP]
                ],
            },
        },
        "counts": {
            "findings": len(findings), "functions": len(functions),
            "analyzed": len(ghidra_funcs),
            "ai_claims": len(ai["claims"]) if ai else 0,
            "ai_unverified": sum(1 for c in (ai["claims"] if ai else []) if c.get("status") == "unverified"),
            "ai_file_level": sum(1 for c in (ai["claims"] if ai else []) if c.get("status") == "file_level"),
        },
        "ai": ai,
        "limitations": _limitations(level, bool(deterministic), ai),
    }


def _limitations(level: str, deterministic: bool, ai: dict | None) -> list[str]:
    out = ["Static analysis only; the sample was not executed.",
           "Decompiled code may be inaccurate; identifiers may be placeholders."]
    if not deterministic:
        out.append("No deterministic tool output -> verdict is unknown.")
    if ai and ai.get("claims"):
        n = sum(1 for c in ai["claims"] if c.get("status") == "unverified")
        if n:
            out.append(f"{n} AI claim(s) could not be verified (not authoritative).")
        nf = sum(1 for c in ai["claims"] if c.get("status") == "file_level")
        if nf:
            out.append(f"{nf} AI claim(s) have file-level evidence but unclear function attribution.")
    return out


def render_json(rep: dict) -> str:
    return json.dumps(rep, ensure_ascii=False, indent=2)


def render_markdown(rep: dict) -> str:
    ident, v, t = rep["identity"], rep["verdict"], rep["tools"]
    L = [
        "# CrowbarAF — Tool Report", "", f"_{rep['generated_at']}_", "",
        "## Identity",
        f"- **SHA-256:** `{ident['sha256']}`",
        f"- **DIE:** {ident['file_type']} / {ident['arch']}  |  **Packer:** {ident['packer']}  |  **Route:** {ident['route']}",
        "",
        "## Verdict",
        f"- **Level:** `{v['level']}` — {v['note']}",
    ]
    if v.get("state"):
        L.append(f"- **State:** `{v['state']}`")
    if v.get("coverage"):
        cov = v["coverage"]
        ratio = float(cov.get("ratio", 0.0) or 0.0)
        L.append(f"- **Coverage:** {cov.get('analyzed', 0)}/{cov.get('total', 0)} "
                 f"({ratio:.0%})")
    if v.get("unknown_reasons"):
        L.append("- **Unknown because:** " + "; ".join(v["unknown_reasons"]))
    if v.get("next_actions"):
        L.append("- **Next:** " + "; ".join(v["next_actions"]))
    L += ["", "## 1) YARA"]
    L += [f"- `{y['rule']}`" + (f" @ {y['address']}" if y.get("address") else "") for y in t["yara"]] or ["- (no matches)"]

    L += ["", "## 2) capa (capabilities)"]
    capa = t["capa"]
    if capa["matched_rules"] or capa["mitre_attack"] or capa["malware_behavior"]:
        for r in capa["matched_rules"]:
            L.append(f"- rule: `{r}`")
        for a in capa["mitre_attack"]:
            L.append(f"- ATT&CK: {a}")
        for m in capa["malware_behavior"]:
            L.append(f"- MBC: {m}")
    else:
        L.append("- (no capabilities found)")

    L += ["", f"## 3) FLOSS (strings/IoC) — total {t['floss']['string_count']}"]
    if t["floss"]["ioc_findings"]:
        L += [f"- **IoC:** {x}" for x in t["floss"]["ioc_findings"]]
    L += [f"- `{s[:90]}`" for s in t["floss"]["strings"][:20]] or ["- (no strings)"]

    L += ["", f"## 4) Import analysis — {t['imports']['import_count']} imports"]
    if t["imports"]["combos"]:
        L += [f"- **combination:** {c}" for c in t["imports"]["combos"]]
    if t["imports"].get("imphash"):
        L.append(f"- **imphash:** `{t['imports']['imphash']}`")
    L += [f"- `{i}`" for i in t["imports"]["list"][:20]] or ["- (no imports)"]

    if t["entropy"]:
        L += ["", "## 5) Entropy / section"]
        L += [f"- {e['value']} ({e['kind']})" for e in t["entropy"]]

    if t.get("pe_metadata"):
        L += ["", "## 5b) PE metadata (signature presence is NOT verified)"]
        L += [f"- {m['kind']}: {m['value']}" for m in t["pe_metadata"]]

    g = t["ghidra"]
    L += ["", "## 6) Ghidra function inventory",
          f"- Functions: {g['function_count']} (decompiled: {g['decompiled']})  |  call edges: {g['call_edges']}  |  decompile warnings: {g['decompile_warnings']}",
          "", "| offset | name | pri | size | interesting |", "|---|---|---|---|---|"]
    for f in g["prioritized"][:25]:
        L.append(f"| `{f['offset']}` | {f['name']} | {f['priority']} | {f['size']} | {'yes' if f['interesting'] else '—'} |")
    if not g["prioritized"]:
        L.append("| - | (no functions) | | | |")

    if rep["ai"]:
        L += ["", "## AI commentary (not authoritative — read with caution)"]
        claims = rep["ai"]["claims"]
        for status, title in CLAIM_GROUPS:
            bucket = [c for c in claims if c.get("status") == status]
            if not bucket:
                continue
            L += ["", f"### {title} — {len(bucket)}"]
            for c in bucket[:30]:
                L.append(f"- `{c.get('offset')}` {str(c.get('text',''))[:120]}")
        if not claims:
            L.append("- (no claims)")

    L += ["", "## Limitations"] + [f"- {x}" for x in rep["limitations"]]
    return "\n".join(L)


def render_html(rep: dict) -> str:
    body = html.escape(render_markdown(rep))
    color = {"high": "#c0392b", "medium": "#e67e22", "unknown": "#7f8c8d"}.get(rep["verdict"]["level"], "#7f8c8d")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>CrowbarAF {rep['identity']['sha256'][:12]}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#222}}
pre{{background:#f6f8fa;padding:1rem;border-radius:8px;white-space:pre-wrap;word-break:break-word}}
.badge{{display:inline-block;padding:.2rem .6rem;border-radius:6px;color:#fff;background:{color};font-weight:600}}</style>
</head><body><p>Verdict: <span class="badge">{html.escape(rep['verdict']['level'])}</span></p><pre>{body}</pre></body></html>"""


def _from_db(sha256: str) -> dict:
    import db
    detail = db.get_sample_details(sha256)
    if detail is None:
        raise SystemExit(f"Not found in DB: {sha256}")
    return {"sample": detail["sample"], "findings": detail["findings"],
            "source_code": detail["functions"], "analysis_report": detail.get("supervisor_report", ""),
            "verdict": detail.get("verdict", {})}


def main() -> None:
    ap = argparse.ArgumentParser(description="CrowbarAF tool report")
    ap.add_argument("state_json", nargs="?", help="state JSON (main.py output)")
    ap.add_argument("--db", help="sample sha256 in the DB")
    ap.add_argument("--trace", help="LLM trace JSON (for AI commentary)")
    ap.add_argument("--format", choices=["md", "html", "json"], default="md")
    ap.add_argument("--out", help="output directory (stdout if omitted)")
    args = ap.parse_args()

    if args.db:
        state = _from_db(args.db)
    elif args.state_json:
        with open(args.state_json, encoding="utf-8") as fh:
            state = json.load(fh)
    else:
        ap.error("state_json or --db is required")

    trace = None
    trace_path = args.trace
    if not trace_path:
        m = re.search(r"Trace:\s*(\S+\.json)", state.get("intent_analysis", "") or "")
        if m:
            trace_path = m.group(1)
    if trace_path and os.path.isfile(trace_path):
        with open(trace_path, encoding="utf-8") as fh:
            trace = json.load(fh)

    rep = build(state, trace)
    out = {"md": render_markdown, "html": render_html, "json": render_json}[args.format](rep)

    if args.out:
        os.makedirs(args.out, exist_ok=True)
        ext = {"md": "md", "html": "html", "json": "json"}[args.format]
        path = os.path.join(args.out, f"{rep['identity']['sha256'][:16] or 'report'}.{ext}")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(path)
    else:
        sys.stdout.write(out + "\n")


if __name__ == "__main__":
    main()

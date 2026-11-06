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

from utils import defang_ioc, defang_text

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
    tlsh_hash = next((f.get("value") for f in _by_source(findings, "tlsh")), "")
    pe_metadata = [{"kind": f.get("kind"), "value": defang_text(f.get("value") or "")}
                   for f in _by_source(findings, "pe_metadata")]
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
        note = defang_text("; ".join(v4.get("reasons") or v4.get("unknown_reasons") or []))
        deterministic = bool(v4.get("critical_findings"))

    ai = None
    if trace:
        claims = []
        for fn in trace.get("functions", []):
            for c in fn.get("claims", []):
                claim = {"offset": fn.get("offset"), "name": fn.get("name"), **c}
                if isinstance(claim.get("text"), str):
                    claim["text"] = defang_text(claim["text"])  # analyst safety
                claims.append(claim)
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
            "unknown_reasons": [defang_text(x) for x in (v4.get("unknown_reasons") or [])],
            "next_actions": [defang_text(x) for x in (v4.get("next_actions") or [])],
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
            # IoCs are defanged (so they are not clickable links); the raw value stays in state/DB.
            "floss": {"strings": [defang_text(s) for s in strings[:FLOSS_CAP]],
                      "string_count": len(strings),
                      "ioc_findings": [defang_ioc(f.get("value") or "") for f in floss_findings],
                      # verified == False: string not found in the file bytes (may be a tool error/fabricated)
                      "ioc_unverified": [defang_ioc(f.get("value") or "") for f in floss_findings
                                         if f.get("verified") is False]},
            "imports": {"list": imports[:IMPORT_CAP], "import_count": len(imports), "combos": combos,
                        "imphash": imphash, "tlsh": tlsh_hash},
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
        unverified = set(t["floss"].get("ioc_unverified") or [])
        L += [f"- **IoC:** {x}" + (" **(Unverified)** — not found in the file bytes; may be a tool "
                                    "error or fabricated, cannot support a malicious verdict"
                                    if x in unverified else "")
              for x in t["floss"]["ioc_findings"]]
    L += [f"- `{s[:90]}`" for s in t["floss"]["strings"][:20]] or ["- (no strings)"]

    L += ["", f"## 4) Import analysis — {t['imports']['import_count']} imports"]
    if t["imports"]["combos"]:
        L += [f"- **combination:** {c}" for c in t["imports"]["combos"]]
    if t["imports"].get("imphash"):
        L.append(f"- **imphash:** `{t['imports']['imphash']}`")
    if t["imports"].get("tlsh"):
        L.append(f"- **TLSH:** `{t['imports']['tlsh']}`")
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


def _esc(value) -> str:
    return html.escape(str(value if value is not None else ""))


def _table(headers: list[str], rows: list[list[str]]) -> str:
    head = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows)
    return f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def render_html(rep: dict) -> str:
    """Readable, self-contained HTML report (no scripts, no external assets)."""
    ident = rep["identity"]
    v = rep["verdict"]
    t = rep["tools"]
    level = str(v.get("level") or "unknown")
    color = {"high": "#b42318", "medium": "#b54708", "unknown": "#667085"}.get(level, "#667085")
    parts: list[str] = []
    parts.append(f'<header><div><h1>CrowbarAF Analysis Report</h1>'
                 f'<p class="muted">Generated {_esc(rep.get("generated_at", ""))}</p></div>'
                 f'<span class="badge" style="background:{color}">{_esc(level)}</span></header>')
    parts.append('<section class="card"><h2>Identity</h2><div class="grid">')
    for label, key in (("SHA-256", "sha256"), ("File type", "file_type"),
                       ("Architecture", "arch"), ("Packer", "packer"),
                       ("Route", "route")):
        parts.append(f'<div><span class="label">{_esc(label)}</span><code>{_esc(ident.get(key, ""))}</code></div>')
    parts.append("</div></section>")

    state = v.get("state") or ""
    parts.append('<section class="card"><h2>Verdict</h2>')
    parts.append(f'<p><span class="badge" style="background:{color}">{_esc(level)}</span> '
                 + (f'<code>{_esc(state)}</code>' if state else "") + '</p>')
    if v.get("note"):
        parts.append(f'<p>{_esc(v["note"])}</p>')
    cov = v.get("coverage") or {}
    if cov:
        ratio = float(cov.get("ratio", 0) or 0)
        parts.append(f'<p class="muted">Coverage: {_esc(cov.get("analyzed", 0))}/{_esc(cov.get("total", 0))} '
                     f'({ratio:.0%}); decompiled: {_esc(cov.get("decompiled", "?"))}; '
                     f'skipped: {_esc(cov.get("skipped", "?"))}</p>')
    if v.get("unknown_reasons"):
        parts.append('<h3>Unknown reasons</h3><ul>' + "".join(f"<li>{_esc(x)}</li>" for x in v["unknown_reasons"]) + "</ul>")
    if v.get("next_actions"):
        parts.append('<h3>Next actions</h3><ul>' + "".join(f"<li>{_esc(x)}</li>" for x in v["next_actions"]) + "</ul>")
    parts.append("</section>")

    parts.append('<section class="card"><h2>Deterministic evidence</h2>')
    yara = t.get("yara") or []
    parts.append(f'<h3>YARA ({len(yara)})</h3>')
    parts.append(_table(["Rule", "Address"], [[_esc(y.get("rule", "")), f"<code>{_esc(y.get('address', ''))}</code>"] for y in yara]) if yara else '<p class="empty">No YARA matches.</p>')
    capa = t.get("capa") or {}
    capa_rows = ([[_esc("rule"), _esc(x)] for x in capa.get("matched_rules", [])]
                 + [[_esc("ATT&CK"), _esc(x)] for x in capa.get("mitre_attack", [])]
                 + [[_esc("MBC"), _esc(x)] for x in capa.get("malware_behavior", [])])
    parts.append(f'<h3>capa ({len(capa_rows)})</h3>')
    parts.append(_table(["Type", "Value"], capa_rows) if capa_rows else '<p class="empty">No capabilities found.</p>')
    floss = t.get("floss") or {}
    parts.append(f'<h3>FLOSS ({_esc(floss.get("string_count", 0))} strings)</h3>')
    unverified = set(floss.get("ioc_unverified") or [])
    ioc_rows = []
    for x in floss.get("ioc_findings") or []:
        flag = ' <span class="warn">(Unverified)</span>' if x in unverified else ""
        ioc_rows.append([f"<code>{_esc(x)}</code>{flag}"])
    if ioc_rows:
        parts.append(_table(["IoC"], ioc_rows))
    strings = floss.get("strings") or []
    if strings:
        parts.append('<details><summary>String sample</summary><pre>' + _esc("\n".join(str(x) for x in strings[:50])) + '</pre></details>')
    parts.append("</section>")

    imports = t.get("imports") or {}
    parts.append('<section class="card"><h2>Imports and grouping</h2>')
    meta = []
    if imports.get("imphash"):
        meta.append(f'<div><span class="label">imphash</span><code>{_esc(imports["imphash"])}</code></div>')
    if imports.get("tlsh"):
        meta.append(f'<div><span class="label">TLSH</span><code>{_esc(imports["tlsh"])}</code></div>')
    if meta:
        parts.append('<div class="grid">' + "".join(meta) + "</div>")
    if imports.get("combos"):
        parts.append('<h3>Import combinations</h3><ul>' + "".join(f"<li>{_esc(x)}</li>" for x in imports["combos"]) + "</ul>")
    parts.append(f'<p class="muted">Imports: {_esc(imports.get("import_count", 0))}</p>')
    if imports.get("list"):
        parts.append('<details><summary>Import list</summary><pre>' + _esc("\n".join(str(x) for x in imports["list"][:80])) + '</pre></details>')
    parts.append("</section>")

    g = t.get("ghidra") or {}
    parts.append('<section class="card"><h2>Ghidra functions</h2>')
    parts.append(f'<p class="muted">Functions: {_esc(g.get("function_count", 0))}; '
                 f'decompiled: {_esc(g.get("decompiled", 0))}; '
                 f'call edges: {_esc(g.get("call_edges", 0))}; '
                 f'warnings: {_esc(g.get("decompile_warnings", 0))}</p>')
    rows = []
    for fn in (g.get("prioritized") or [])[:100]:
        summary = fn.get("llm_summary") or ""
        rows.append([f"<code>{_esc(fn.get('offset', ''))}</code>", _esc(fn.get("name", "")),
                     _esc(fn.get("priority", 0)), _esc(fn.get("size", 0)),
                     "yes" if fn.get("interesting") else "-", _esc(summary[:220])])
    parts.append(_table(["Offset", "Name", "Priority", "Size", "Interesting", "LLM summary"], rows)
                 if rows else '<p class="empty">No functions.</p>')
    parts.append("</section>")

    ai = rep.get("ai")
    if ai:
        parts.append('<section class="card"><h2>AI commentary</h2><p class="warn">Model output is not authoritative; verify against evidence.</p>')
        claims = ai.get("claims") or []
        for status, title in CLAIM_GROUPS:
            bucket = [c for c in claims if c.get("status") == status]
            if not bucket:
                continue
            parts.append(f"<h3>{_esc(title)} ({len(bucket)})</h3><ul>")
            for c in bucket[:50]:
                parts.append(f"<li><code>{_esc(c.get('offset', ''))}</code> {_esc(str(c.get('text', ''))[:240])}</li>")
            parts.append("</ul>")
        if not claims:
            parts.append('<p class="empty">No claims.</p>')
        parts.append("</section>")

    parts.append('<section class="card"><h2>Limitations</h2><ul>')
    for x in rep.get("limitations") or []:
        parts.append(f"<li>{_esc(x)}</li>")
    parts.append("</ul></section>")
    parts.append('<footer>CrowbarAF - deterministic evidence first. No result here is a guarantee of safety.</footer>')

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CrowbarAF report - {_esc(ident.get('sha256', '')[:16])}</title>
<style>
:root {{ --bg:#f5f7fb; --card:#fff; --text:#1d2939; --muted:#667085; --line:#e4e7ec; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--text); font:14px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }}
header {{ max-width:1100px; margin:0 auto; padding:28px 24px 8px; display:flex; justify-content:space-between; gap:16px; align-items:flex-start; }}
h1 {{ margin:0; font-size:24px; letter-spacing:-.2px; }}
h2 {{ margin:0 0 12px; font-size:16px; }}
h3 {{ margin:18px 0 8px; font-size:14px; }}
main {{ max-width:1100px; margin:0 auto; padding:0 24px 40px; }}
.card {{ background:var(--card); border:1px solid var(--line); border-radius:10px; padding:18px 20px; margin-top:14px; box-shadow:0 1px 2px rgba(16,24,40,.04); }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:12px; }}
.label {{ display:block; color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.5px; }}
code {{ font-family:ui-monospace,SFMono-Regular,Consolas,monospace; font-size:12.5px; overflow-wrap:anywhere; }}
pre {{ background:#0f172a; color:#e2e8f0; border-radius:8px; padding:12px; white-space:pre-wrap; overflow-wrap:anywhere; max-height:420px; overflow:auto; }}
.table-wrap {{ overflow:auto; }}
table {{ width:100%; border-collapse:collapse; }}
th, td {{ text-align:left; padding:7px 9px; border-bottom:1px solid var(--line); vertical-align:top; }}
th {{ color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.4px; }}
tr:last-child td {{ border-bottom:0; }}
.badge {{ display:inline-block; padding:4px 10px; border-radius:999px; color:#fff; font-weight:700; }}
.muted {{ color:var(--muted); }}
.warn {{ color:#b54708; font-weight:600; }}
.empty {{ color:var(--muted); }}
details {{ margin-top:10px; }} summary {{ cursor:pointer; color:var(--muted); }}
footer {{ max-width:1100px; margin:0 auto; padding:18px 24px 40px; color:var(--muted); font-size:12px; }}
@media print {{ body {{ background:#fff; }} .card {{ box-shadow:none; break-inside:avoid; }} details {{ display:block; }} }}
</style></head><body>
{''.join(parts)}
</body></html>"""

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

"""Araç-öncelikli rapor: deterministik araçların toplu çıktısı + (opsiyonel) AI yorumu.

İlke:
  * **Araç çıktısı** (DIE/YARA/capa/FLOSS/import/entropy/Ghidra) ana içeriktir.
  * **AI yorumu** ayrı ve işaretlidir ("doğrulanmamış olabilir").
  * Kanıt yoksa karar **"belirsiz"**dir, asla "temiz" değil.

Kullanım:
    python report.py <state.json> [--format md|html|json] [--out reports/]
    python report.py --db <sha256> [--format md] [--out reports/]
    # AI iddialarını da eklemek için: --trace runs/llm_trace_X.json
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


def _by_source(findings: list[dict], source: str) -> list[dict]:
    return [f for f in findings if f.get("source") == source]


def _has(fn: dict) -> bool:
    """Fonksiyon 'ilgi çekici' mi (capa eşleşmesi / yüksek öncelik)?"""
    return bool(fn.get("capa_hits")) or (fn.get("priority") or 0) >= 4


def build(state: dict, trace: dict | None = None) -> dict:
    sample = state.get("sample", {}) or {}
    findings = state.get("findings", []) or []
    caps = state.get("capabilities", {}) or {}
    functions = state.get("source_code", []) or []
    strings = state.get("extracted_strings", []) or []

    # --- araç bölümleri (deterministik) ---
    yara = [{"rule": f.get("value"), "address": f.get("address")} for f in _by_source(findings, "yara")]
    imports = [f.get("value") for f in _by_source(findings, "import")]
    combos = [f.get("value") for f in _by_source(findings, "import_combo")]
    entropy = [{"value": f.get("value"), "kind": f.get("kind")} for f in
               (_by_source(findings, "entropy") + _by_source(findings, "pefile_entropy"))]
    floss_findings = _by_source(findings, "floss")

    ghidra_funcs = [f for f in functions if (f.get("c_code") or "").strip()]
    edges = sum(len(f.get("callees", []) or []) for f in functions)
    warnings = sum(len(f.get("decompile_warnings", []) or []) for f in functions)
    prioritized = sorted(functions, key=lambda x: (-(x.get("priority") or 0), x.get("offset") or ""))

    deterministic = bool(yara or caps.get("matched_rules") or combos or imports or entropy)
    if deterministic:
        level, note = "yuksek", "Deterministik araç(lar) bulgu üretti."
    elif floss_findings or strings:
        level, note = "orta", "Yalnızca string/IoC düzeyinde çıktı var."
    else:
        level, note = "belirsiz", ("Araç çıktısı yok. Bu dosya 'temiz' DEĞİL; "
                                   "'belirsiz'dir, manuel inceleme gerekir.")

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
        "verdict": {"level": level, "note": note, "has_deterministic_evidence": deterministic},
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
            "imports": {"list": imports[:IMPORT_CAP], "import_count": len(imports), "combos": combos},
            "entropy": entropy,
            "ghidra": {
                "function_count": len(functions), "decompiled": len(ghidra_funcs),
                "call_edges": edges, "decompile_warnings": warnings,
                "prioritized": [
                    {"offset": f.get("offset"), "name": f.get("name"), "priority": f.get("priority", 0),
                     "size": f.get("size", 0), "interesting": _has(f),
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
    out = ["Statik analiz; dosya çalıştırılmadı.",
           "Decompile çıktısı hatalı olabilir; isimler yer tutucu olabilir."]
    if not deterministic:
        out.append("Deterministik araç çıktısı yok → karar belirsiz.")
    if ai and ai.get("claims"):
        n = sum(1 for c in ai["claims"] if c.get("status") == "unverified")
        if n:
            out.append(f"{n} AI iddiası doğrulanamadı (emin değilim) — otorite değildir.")
        nf = sum(1 for c in ai["claims"] if c.get("status") == "file_level")
        if nf:
            out.append(f"{nf} AI iddiası dosya düzeyinde kanıtlı ama fonksiyon atfı belirsiz.")
    return out


def render_json(rep: dict) -> str:
    return json.dumps(rep, ensure_ascii=False, indent=2)


def render_markdown(rep: dict) -> str:
    ident, v, t = rep["identity"], rep["verdict"], rep["tools"]
    L = [
        "# CrowbarAF — Araç Raporu", "", f"_{rep['generated_at']}_", "",
        "## Kimlik",
        f"- **SHA-256:** `{ident['sha256']}`",
        f"- **DIE:** {ident['file_type']} / {ident['arch']}  |  **Packer:** {ident['packer']}  |  **Rota:** {ident['route']}",
        "",
        "## Karar",
        f"- **Düzey:** `{v['level']}` — {v['note']}",
        "",
        "## 1) YARA",
    ]
    L += [f"- `{y['rule']}`" + (f" @ {y['address']}" if y.get("address") else "") for y in t["yara"]] or ["- (eşleşme yok)"]

    L += ["", "## 2) capa (yetenekler)"]
    capa = t["capa"]
    if capa["matched_rules"] or capa["mitre_attack"] or capa["malware_behavior"]:
        for r in capa["matched_rules"]:
            L.append(f"- kural: `{r}`")
        for a in capa["mitre_attack"]:
            L.append(f"- ATT&CK: {a}")
        for m in capa["malware_behavior"]:
            L.append(f"- MBC: {m}")
    else:
        L.append("- (yetenek bulunamadı)")

    L += ["", f"## 3) FLOSS (string/IoC) — toplam {t['floss']['string_count']}"]
    if t["floss"]["ioc_findings"]:
        L += [f"- **IoC:** {x}" for x in t["floss"]["ioc_findings"]]
    L += [f"- `{s[:90]}`" for s in t["floss"]["strings"][:20]] or ["- (string yok)"]

    L += ["", f"## 4) Import analizi — {t['imports']['import_count']} import"]
    if t["imports"]["combos"]:
        L += [f"- ⚠️ **kombinasyon:** {c}" for c in t["imports"]["combos"]]
    L += [f"- `{i}`" for i in t["imports"]["list"][:20]] or ["- (import yok)"]

    if t["entropy"]:
        L += ["", "## 5) Entropy / section"]
        L += [f"- {e['value']} ({e['kind']})" for e in t["entropy"]]

    g = t["ghidra"]
    L += ["", "## 6) Ghidra fonksiyon envanteri",
          f"- Fonksiyon: {g['function_count']} (decompile: {g['decompiled']})  |  çağrı kenarı: {g['call_edges']}  |  decompile uyarısı: {g['decompile_warnings']}",
          "", "| offset | isim | pri | boyut | ilgi |", "|---|---|---|---|---|"]
    for f in g["prioritized"][:25]:
        L.append(f"| `{f['offset']}` | {f['name']} | {f['priority']} | {f['size']} | {'evet' if f['interesting'] else '—'} |")
    if not g["prioritized"]:
        L.append("| - | (fonksiyon yok) | | | |")

    if rep["ai"]:
        L += ["", "## AI yorumu (otorite değil — ihtiyatla oku)"]
        groups = [
            ("verified_claim", "### Doğrulanmış iddialar (fonksiyona yerel kanıt)"),
            ("verified_observation", "### Kod alıntısına dayalı gözlemler"),
            ("file_level", "### Dosya düzeyi kanıt (fonksiyon atfı belirsiz)"),
            ("unverified", "### Doğrulanamayan iddialar (emin değilim)"),
        ]
        claims = rep["ai"]["claims"]
        for status, title in groups:
            bucket = [c for c in claims if c.get("status") == status]
            if not bucket:
                continue
            L += ["", f"{title} — {len(bucket)} adet"]
            for c in bucket[:30]:
                L.append(f"- `{c.get('offset')}` {str(c.get('text',''))[:120]}")
        if not claims:
            L.append("- (iddia yok)")

    L += ["", "## Sınırlılıklar"] + [f"- {x}" for x in rep["limitations"]]
    return "\n".join(L)


def render_html(rep: dict) -> str:
    body = html.escape(render_markdown(rep))
    color = {"yuksek": "#c0392b", "orta": "#e67e22", "belirsiz": "#7f8c8d"}.get(rep["verdict"]["level"], "#7f8c8d")
    return f"""<!doctype html>
<html lang="tr"><head><meta charset="utf-8"><title>CrowbarAF {rep['identity']['sha256'][:12]}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#222}}
pre{{background:#f6f8fa;padding:1rem;border-radius:8px;white-space:pre-wrap;word-break:break-word}}
.badge{{display:inline-block;padding:.2rem .6rem;border-radius:6px;color:#fff;background:{color};font-weight:600}}</style>
</head><body><p>Karar: <span class="badge">{html.escape(rep['verdict']['level'])}</span></p><pre>{body}</pre></body></html>"""


def _from_db(sha256: str) -> dict:
    import db
    detail = db.get_sample_details(sha256)
    if detail is None:
        raise SystemExit(f"DB'de bulunamadı: {sha256}")
    return {"sample": detail["sample"], "findings": detail["findings"],
            "source_code": detail["functions"], "analysis_report": detail.get("supervisor_report", "")}


def main() -> None:
    ap = argparse.ArgumentParser(description="CrowbarAF araç raporu")
    ap.add_argument("state_json", nargs="?", help="state JSON (main.py çıktısı)")
    ap.add_argument("--db", help="DB'deki sha256")
    ap.add_argument("--trace", help="LLM iz JSON'u (AI yorumu için)")
    ap.add_argument("--format", choices=["md", "html", "json"], default="md")
    ap.add_argument("--out", help="çıktı dizini (yoksa stdout)")
    args = ap.parse_args()

    if args.db:
        state = _from_db(args.db)
    elif args.state_json:
        with open(args.state_json, encoding="utf-8") as fh:
            state = json.load(fh)
    else:
        ap.error("state_json veya --db gerekli")

    trace = None
    trace_path = args.trace
    if not trace_path:
        m = re.search(r"Iz:\s*(\S+\.json)", state.get("intent_analysis", "") or "")
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

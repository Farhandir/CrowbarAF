"""Crowbar - Otonom Statik Zararlı Yazılım Analiz Sistemi (giriş noktası).

Kullanım:
    python main.py <analiz_edilecek_dosya>     # CLI: analizi çalıştırır, state'i JSON basar
    python main.py --diagram                   # Mermaid grafik çıktısı
    python main.py --serve [--host H --port P] # Web arayüzü + API (http://127.0.0.1:8000)
    uvicorn main:app                           # aynı arayüz, uvicorn ile

API:
    POST /api/upload            dosya yükler, analizi arka planda başlatır (202)
    GET  /api/samples           analiz edilmiş örneklerin listesi
    GET  /api/samples/{sha256}  bulgular, fonksiyonlar ve supervisor raporu
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import shutil
import sys
import tempfile
import threading
from typing import Any

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse

import db
from graph import build_graph
from nodes import compute_sha256
from state import AgentState

logger = logging.getLogger(__name__)

MAX_UPLOAD_BYTES = int(os.environ.get("CROWBAR_MAX_UPLOAD_MB", "200")) * 1024 * 1024
UPLOAD_CHUNK_SIZE = 1024 * 1024

app = FastAPI(title="CrowbarAF", description="Otonom statik zararlı yazılım analizi")

# sha256 -> {"status": "running" | "error", "error": str}; başarılı işler kayıttan düşer
_JOBS: dict[str, dict[str, str]] = {}
_JOBS_LOCK = threading.Lock()
_GRAPH: Any = None
_GRAPH_LOCK = threading.Lock()


def _get_graph() -> Any:
    """LangGraph'ı bir kez derler (thread-safe)."""
    global _GRAPH
    with _GRAPH_LOCK:
        if _GRAPH is None:
            _GRAPH = build_graph()
        return _GRAPH


# --------------------------------------------------------------------------- #
# Yükleme + analiz
# --------------------------------------------------------------------------- #
def _safe_filename(name: str | None) -> str:
    """Yol bileşenlerini ve kontrol karakterlerini temizler (path traversal'a karşı)."""
    base = os.path.basename((name or "").replace("\\", "/"))
    base = re.sub(r"[\x00-\x1f<>:\"|?*]", "_", base).strip(" .")
    return base or "sample.bin"


def _save_upload(upload: UploadFile, dest: str) -> int:
    """Yüklenen dosyayı parça parça diske yazar; boyut sınırını aşarsa 413 fırlatır."""
    size = 0
    with open(dest, "wb") as out:
        while chunk := upload.file.read(UPLOAD_CHUNK_SIZE):
            size += len(chunk)
            if size > MAX_UPLOAD_BYTES:
                raise HTTPException(status_code=413, detail=f"Dosya {MAX_UPLOAD_BYTES // (1024 * 1024)} MB sınırını aşıyor")
            out.write(chunk)
    return size


def _run_analysis(path: str, tmp_dir: str, sha256: str) -> None:
    """Graph'ı çalıştırır (arka plan görevi); iş bitince geçici klasörü siler."""
    try:
        _get_graph().invoke(AgentState(file_path=path))
        with _JOBS_LOCK:
            _JOBS.pop(sha256, None)
    except Exception as exc:  # noqa: BLE001 - arka plan görevi sunucuyu düşürmemeli
        logger.exception("[api] analiz başarısız: %s", sha256)
        with _JOBS_LOCK:
            _JOBS[sha256] = {"status": "error", "error": f"{type(exc).__name__}: {exc}"}
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@app.post("/api/upload", status_code=202)
def upload(background_tasks: BackgroundTasks, file: UploadFile = File(...)) -> dict[str, str]:
    """Dosyayı geçici klasöre kaydeder ve analizi arka planda başlatır.

    Dönen ``sha256`` ile ``GET /api/samples/{sha256}`` yoklanarak sonuç beklenir.
    """
    filename = _safe_filename(file.filename)
    tmp_dir = tempfile.mkdtemp(prefix="crowbaraf_")
    path = os.path.join(tmp_dir, filename)
    try:
        size = _save_upload(file, path)
        if size == 0:
            raise HTTPException(status_code=400, detail="Boş dosya")
        sha256 = compute_sha256(path)

        with _JOBS_LOCK:
            if _JOBS.get(sha256, {}).get("status") == "running":
                shutil.rmtree(tmp_dir, ignore_errors=True)
                return {"sha256": sha256, "filename": filename, "status": "running"}
            _JOBS[sha256] = {"status": "running", "error": ""}
    except Exception:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise

    background_tasks.add_task(_run_analysis, path, tmp_dir, sha256)
    return {"sha256": sha256, "filename": filename, "status": "running"}


# --------------------------------------------------------------------------- #
# Okuma uç noktaları
# --------------------------------------------------------------------------- #
@app.get("/api/samples")
def list_samples() -> list[dict[str, Any]]:
    """Veritabanındaki tüm analiz edilmiş örnekler (en yeni önce)."""
    return db.get_all_samples()


@app.get("/api/samples/{sha256}")
def sample_details(sha256: str) -> Any:
    """Bulgular, fonksiyonlar ve supervisor raporu. Analiz sürüyorsa ``analysis_status`` belirtir."""
    details = db.get_sample_details(sha256)
    with _JOBS_LOCK:
        job = dict(_JOBS.get(sha256, {}))

    if details is None:
        if job.get("status") == "running":
            return JSONResponse(status_code=202, content={"sha256": sha256, "analysis_status": "running"})
        if job.get("status") == "error":
            return JSONResponse(
                status_code=500,
                content={"sha256": sha256, "analysis_status": "error", "error": job.get("error", "")},
            )
        raise HTTPException(status_code=404, detail="Örnek bulunamadı")

    details["analysis_status"] = job.get("status", "done")
    if job.get("error"):
        details["error"] = job["error"]
    return details


# --------------------------------------------------------------------------- #
# Arayüz (tek sayfa, harici bağımlılık yok: çevrimdışı çalışır)
# --------------------------------------------------------------------------- #
INDEX_HTML = r"""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CrowbarAF</title>
<style>
  :root {
    --bg: #0f1217; --panel: #171b22; --panel2: #1e232c; --border: #2a303b;
    --text: #e6e9ef; --muted: #8b93a1; --accent: #4f9cf9; --ok: #3ecf8e; --warn: #f5b93d; --bad: #f05d5e;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text);
         font: 14px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
  header { padding: 18px 28px; border-bottom: 1px solid var(--border); display: flex; align-items: baseline; gap: 14px; }
  header h1 { margin: 0; font-size: 20px; letter-spacing: .3px; }
  header span { color: var(--muted); }
  main { max-width: 1180px; margin: 0 auto; padding: 24px 28px 60px; display: grid; gap: 20px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 18px 20px; }
  .card h2 { margin: 0 0 12px; font-size: 15px; color: var(--muted); font-weight: 600; text-transform: uppercase; letter-spacing: .6px; }
  .row { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
  input[type=file] { color: var(--muted); flex: 1; min-width: 240px; padding: 8px; background: var(--panel2);
                     border: 1px dashed var(--border); border-radius: 8px; }
  button { background: var(--accent); color: #07121f; border: 0; border-radius: 8px; padding: 9px 16px;
           font-weight: 600; cursor: pointer; }
  button:disabled { opacity: .5; cursor: default; }
  button.ghost { background: transparent; color: var(--accent); border: 1px solid var(--border); }
  #status { margin-top: 10px; color: var(--muted); min-height: 20px; }
  #status.err { color: var(--bad); } #status.ok { color: var(--ok); }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
  th { color: var(--muted); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: .5px; }
  tbody tr.sample { cursor: pointer; }
  tbody tr.sample:hover, tbody tr.sel { background: var(--panel2); }
  code, pre { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12.5px; }
  .muted { color: var(--muted); }
  .chip { display: inline-block; padding: 1px 8px; border-radius: 99px; background: var(--panel2);
          border: 1px solid var(--border); font-size: 12px; margin-right: 6px; }
  .chip.hi { color: var(--warn); border-color: #5a4a1d; } .chip.ok { color: var(--ok); } .chip.bad { color: var(--bad); }
  pre { background: #0b0e13; border: 1px solid var(--border); border-radius: 8px; padding: 12px; overflow: auto;
        white-space: pre-wrap; word-break: break-word; margin: 8px 0 0; max-height: 420px; }
  details { border: 1px solid var(--border); border-radius: 8px; padding: 8px 12px; margin-bottom: 8px; background: var(--panel2); }
  details summary { cursor: pointer; }
  .fn-row { display: inline-flex; gap: 10px; align-items: center; flex-wrap: wrap; }
  .fn-summary { color: var(--muted); font-style: italic; margin: 3px 0 0 18px; font-size: 13px; }
  /* Karar rozetleri */
  .badge { display: inline-block; padding: 2px 10px; border-radius: 99px; font-size: 12px; font-weight: 700;
           letter-spacing: .3px; background: #4b5563; color: #f3f4f6; white-space: nowrap; }
  .badge.malicious { background: #d63031; color: #fff; }
  .badge.needs_review { background: #f5a623; color: #000; }
  .badge.unknown, .badge.no_evidence { background: #6b7280; color: #fff; }
  .kv { margin: 6px 0; } .kv b { color: var(--muted); font-weight: 600; margin-right: 6px; }
  .banner { padding: 8px 12px; border-radius: 8px; background: #2a2412; color: var(--warn); margin-bottom: 12px; }
  .empty { color: var(--muted); padding: 14px 4px; }
</style>
</head>
<body>
<header><h1>CrowbarAF</h1><span>Otonom statik zararlı yazılım analizi</span></header>
<main>
  <section class="card">
    <h2>Dosya yükle</h2>
    <div class="row">
      <input type="file" id="file">
      <button id="upload">Yükle ve analiz et</button>
    </div>
    <div id="status"></div>
  </section>

  <section class="card">
    <div class="row" style="justify-content: space-between">
      <h2 style="margin: 0">Analiz edilmiş örnekler</h2>
      <button class="ghost" id="refresh">Yenile</button>
    </div>
    <table>
      <thead><tr><th>SHA-256</th><th>Karar</th><th>Tür</th><th>Rota</th><th>Packer</th><th>Mimari</th><th>Bulgu</th><th>Fonksiyon</th><th>Rapor</th></tr></thead>
      <tbody id="samples"></tbody>
    </table>
    <div id="samples-empty" class="empty" hidden>Henüz analiz edilmiş örnek yok.</div>
  </section>

  <section class="card" id="detail" hidden></section>
</main>

<script>
const $ = (sel) => document.querySelector(sel);

// Tüm dinamik metin textContent / text node ile eklenir (örnekten gelen veriye güvenilmez).
function el(tag, props = {}, ...kids) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const kid of kids) if (kid !== null && kid !== undefined) node.append(kid);
  return node;
}

async function api(path, options) {
  const res = await fetch(path, options);
  let body = null;
  try { body = await res.json(); } catch (_) { /* gövde yok */ }
  return { status: res.status, ok: res.ok, body };
}

function setStatus(text, kind = "") {
  const s = $("#status");
  s.textContent = text;
  s.className = kind;
}

let selected = null;
let pollTimer = null;

async function loadSamples() {
  const { ok, body } = await api("/api/samples");
  const tbody = $("#samples");
  tbody.replaceChildren();
  const list = ok && Array.isArray(body) ? body : [];
  $("#samples-empty").hidden = list.length > 0;
  for (const s of list) {
    const tr = el("tr", { class: "sample" + (s.sha256 === selected ? " sel" : ""), onclick: () => showDetail(s.sha256) },
      el("td", {}, el("code", { text: s.sha256.slice(0, 16) + "…", title: s.sha256 })),
      el("td", {}, verdictBadge(s.verdict)),
      el("td", { text: s.file_type }),
      el("td", {}, el("span", { class: "chip", text: s.route })),
      el("td", { text: s.packer }),
      el("td", { text: s.arch }),
      el("td", { text: String(s.findings_count) }),
      el("td", { text: String(s.functions_count) }),
      el("td", { text: s.has_report ? "var" : "—" }));
    tbody.append(tr);
  }
}

function kv(label, value) {
  return el("div", { class: "kv" }, el("b", { text: label }), value);
}

// Karar rozeti. CSS sınıfı yalnızca bilinen değerlerden seçilir (veritabanından gelen metin sınıf adı olmaz).
const KNOWN_VERDICTS = ["malicious", "needs_review", "unknown", "no_evidence"];
function verdictBadge(verdict) {
  const name = verdict && typeof verdict.verdict === "string" ? verdict.verdict : "";
  if (!name) return el("span", { class: "muted", text: "—" });
  return el("span", { class: "badge" + (KNOWN_VERDICTS.includes(name) ? " " + name : ""), text: name });
}

function renderFunction(fn) {
  const summary = el("summary", {},
    el("span", { class: "fn-row" },
      el("code", { text: fn.name || "(adsız)" }),
      el("span", { class: "muted", text: fn.offset || "—" }),
      el("span", { class: "chip" + (fn.priority > 0 ? " hi" : ""), text: "öncelik " + fn.priority }),
      fn.size ? el("span", { class: "chip", text: fn.size + " B" }) : null,
      fn.is_library ? el("span", { class: "chip", text: "kütüphane" }) : null),
    // LLM özeti fonksiyon adının hemen altında (soluk, italik)
    fn.llm_summary ? el("div", { class: "fn-summary", text: fn.llm_summary }) : null);
  const body = [];
  if (fn.capa_hits.length) body.push(kv("capa", fn.capa_hits.join(", ")));
  if (fn.callees.length) body.push(kv("Çağırdıkları", fn.callees.join(", ")));
  if (fn.xrefs.length) body.push(kv("Referanslar", fn.xrefs.join(", ")));
  if (fn.decompile_warnings.length) body.push(kv("Uyarılar", fn.decompile_warnings.join("; ")));
  if (fn.c_code) body.push(el("pre", { text: fn.c_code }));
  return el("details", {}, summary, ...body);
}

function renderDetail(d) {
  const box = $("#detail");
  box.replaceChildren();
  box.hidden = false;
  const s = d.sample;

  box.append(el("h2", { text: "Örnek detayı" }),
    el("div", { class: "kv" }, el("code", { text: s.sha256 })),
    el("div", { class: "kv" },
      el("span", { class: "chip", text: s.file_type }), el("span", { class: "chip", text: s.route }),
      el("span", { class: "chip", text: "packer: " + s.packer }), el("span", { class: "chip", text: s.arch })),
    kv("Karar", verdictBadge(d.verdict)));
  const v = d.verdict || {};
  const notes = [...(v.reasons || []), ...(v.unknown_reasons || [])].map(String);
  if (notes.length) box.append(el("div", { class: "kv muted", text: notes.join(" · ") }));
  if (v.coverage && typeof v.coverage.ratio === "number") box.append(el("div", { class: "kv muted", text: "Kapsam: " + Math.round(v.coverage.ratio * 100) + "%" }));

  if (d.analysis_status === "running") box.append(el("div", { class: "banner", text: "Yeniden analiz sürüyor; gösterilen veri önceki çalıştırmaya ait." }));
  if (d.error) box.append(el("div", { class: "banner", text: "Son analiz hatası: " + d.error }));

  box.append(el("h2", { text: "Supervisor raporu", style: "margin-top:18px" }));
  box.append(d.supervisor_report ? el("pre", { text: d.supervisor_report }) : el("div", { class: "empty", text: "Rapor yok." }));

  box.append(el("h2", { text: "Bulgular (" + d.findings.length + ")", style: "margin-top:18px" }));
  if (d.findings.length) {
    const tbody = el("tbody");
    for (const f of d.findings) {
      tbody.append(el("tr", {},
        el("td", { text: f.source }), el("td", { text: f.kind }),
        el("td", {}, el("code", { text: f.value })), el("td", { text: f.address || "" }),
        el("td", { text: String(f.confidence) })));
    }
    box.append(el("table", {},
      el("thead", {}, el("tr", {}, ...["Kaynak", "Tür", "Değer", "Adres", "Güven"].map((h) => el("th", { text: h })))),
      tbody));
  } else {
    box.append(el("div", { class: "empty", text: "Bulgu yok." }));
  }

  box.append(el("h2", { text: "Fonksiyonlar (" + d.functions.length + ")", style: "margin-top:18px" }));
  if (d.functions.length) for (const fn of d.functions) box.append(renderFunction(fn));
  else box.append(el("div", { class: "empty", text: "Fonksiyon yok." }));
}

async function showDetail(sha256) {
  selected = sha256;
  const { status, body } = await api("/api/samples/" + encodeURIComponent(sha256));
  if (status === 200) renderDetail(body);
  else if (status === 202) setStatus("Analiz sürüyor…");
  else setStatus((body && (body.detail || body.error)) || "Detay alınamadı", "err");
  loadSamples();
}

function stopPolling() { if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } }

function pollUntilDone(sha256) {
  stopPolling();
  pollTimer = setInterval(async () => {
    const { status, body } = await api("/api/samples/" + encodeURIComponent(sha256));
    if (status === 202 || (status === 200 && body.analysis_status === "running")) return;
    stopPolling();
    $("#upload").disabled = false;
    if (status === 200 && body.analysis_status === "done") {
      setStatus("Analiz tamamlandı.", "ok");
      selected = sha256;
      renderDetail(body);
    } else {
      setStatus("Analiz başarısız: " + ((body && (body.error || body.detail)) || status), "err");
    }
    loadSamples();
  }, 3000);
}

async function upload() {
  const input = $("#file");
  if (!input.files.length) { setStatus("Önce bir dosya seçin.", "err"); return; }
  const form = new FormData();
  form.append("file", input.files[0]);
  $("#upload").disabled = true;
  setStatus("Yükleniyor…");
  let res;
  try {
    res = await api("/api/upload", { method: "POST", body: form });
  } catch (e) {
    $("#upload").disabled = false;
    setStatus("Yükleme başarısız: " + e, "err");
    return;
  }
  if (res.status !== 202) {
    $("#upload").disabled = false;
    setStatus("Yükleme başarısız: " + ((res.body && res.body.detail) || res.status), "err");
    return;
  }
  setStatus("Analiz sürüyor (" + res.body.filename + ")… büyük dosyalarda dakikalar sürebilir.");
  pollUntilDone(res.body.sha256);
}

$("#upload").addEventListener("click", upload);
$("#refresh").addEventListener("click", loadSamples);
loadSamples();
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return INDEX_HTML


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main() -> None:
    # Windows konsolu varsayılan olarak cp1252 kullanır; Türkçe karakterler için UTF-8 zorla.
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="Crowbar statik analiz hattı")
    parser.add_argument("file_path", nargs="?", help="Analiz edilecek dosya")
    parser.add_argument("--diagram", action="store_true", help="Graph'i Mermaid olarak yazdır")
    parser.add_argument("--serve", action="store_true", help="Web arayüzünü ve API'yi başlat")
    parser.add_argument("--host", default="127.0.0.1", help="--serve için adres (varsayılan: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="--serve için port (varsayılan: 8000)")
    parser.add_argument("--no-llm", action="store_true",
                        help="LLM çağrısı yapmadan deterministik state üret (offline VM)")
    parser.add_argument("--no-db", action="store_true", help="SQLite yazmayı atla (offline VM)")
    parser.add_argument("--out", help="State JSON dosyası (verilmezse stdout)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    if args.no_llm:
        os.environ["CROWBAR_SKIP_LLM"] = "1"
    if args.no_db:
        os.environ["CROWBAR_SKIP_DB"] = "1"

    if args.serve:
        import uvicorn

        uvicorn.run(app, host=args.host, port=args.port)
        return

    compiled = build_graph()

    if args.diagram:
        print(compiled.get_graph().draw_mermaid())
        return
    if not args.file_path:
        parser.error("file_path gerekli")

    result = compiled.invoke(AgentState(file_path=args.file_path))
    text = AgentState(**result).model_dump_json(indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        try:
            os.chmod(args.out, 0o600)
        except OSError:
            pass
        logger.info("[main] state yazıldı: %s", args.out)
    else:
        print(text)


if __name__ == "__main__":
    main()

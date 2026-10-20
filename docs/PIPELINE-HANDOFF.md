# CrowbarAF — Pipeline Devir Belgesi (LLM katmanına kadar)

Bu belge, CrowbarAF'ın **LLM katmanına kadar** olan kısmında ne olduğunu, ne
kaldığını ve **LLM katmanının beklediği veri sözleşmesini** tanımlar.

> LLM katmanı (ai_* düğümleri, context paketleme, kanıt doğrulayıcı) ayrı bir
> kişide. Bu belgedeki **veri sözleşmesi** doldurulduğu anda iki taraf paralel
> çalışabilir.

---

## 1. Mevcut durum (commit `73beb8f`)

### Çalışan / hazır
| Dosya | İçerik |
|---|---|
| `state.py` | `AgentState`, `SampleInfo` (`sample`), `DecompiledFunction`, `ghidra_hints` |
| `graph.py` | LangGraph iskeleti + koşullu yönlendirme (`route_after_entry`) |
| `nodes.py` | `entry_node`, `unpack_native_node`, `compute_sha256`, `run_die`, `run_yara`, `decide_route`, `filter_iocs`, `summarize_capa`, `extract_ghidra_hints`, `run_floss`, `run_capa`, `deep_inspection_node` |
| `ghidra_runner.py` | `analyzeHeadless` orkestrasyonu, timeout, temp temizliği (`ghidra_input.json`: hints + findings + combo_apis) |
| `export_functions.py` | Ghidra postScript (PyGhidra/Python 3): tüm fonksiyonları puanlar, Top-100'ü decompile eder |
| `import_combos.py` | Import kombinasyon kuralları (`nodes.py` ve `ghidra_runner.py` ortak) |
| `tests/test_nodes.py` | 53 test (saf mantık) — geçiyor |

### Doğrulanmış teknik notlar
- Ghidra **12.1.4 + JDK** gerekiyor; JRE yetmiyor.
- Ghidra 12'de **Jython varsayılan değil**; `export_functions.py` bu yüzden
  PyGhidra / Python 3'e taşındı (bkz. §5 tuzak 1).
- `.pyc`/`__pycache__` commit'lenmiş; `.gitignore` yok.

---

## 2. Eksikler — düğüm bazında

| Düğüm | Durum | Yapılacak | Kabul kriteri |
|---|---|---|---|
| `entry_node` | **done** | SHA-256 (`compute_sha256`) + `diec --json` (`run_die`) + YARA (`run_yara`, `yara-python`/kural dizini yoksa `[]`) + `decide_route`. Çıktı: `sample` (`sha256`, `file_type`, `arch`, `packer`, `route`), `route_flag`, `yara_results` | Araç yoksa çökmez; `sample` varsayılanları (`"unknown"`) korunur, `route_flag` yine belirlenir. Testler: `tests/test_entry_node.py` |
| `unpack_native_node` | **done (UPX)** | `sample.packer` içinde `upx` varsa `upx -d -o <file>.unpacked <file>`; başarılıysa `file_path` açılmış dosyaya güncellenir (`sample.sha256` orijinal kalır). UPX dışı packer'lar (ASPack, Themida vb.) **yok** | UPX değilse / `upx` yok / timeout / bozuk başlık → `{}` (orijinal dosyayla devam) |
| `unpack_python_node` | **done (araçlarla doğrulanmadı)** | `sample.route == "python"` ise `pyinstxtractor` (geçici dizinde) → ana `.pyc` (exe adı / "Possible entry point" / en büyük) → `pycdc`, olmazsa `decompyle3`. Çıktı: `source_code=[DecompiledFunction(name="main_script", priority=10, c_code=...)]` | Rota farklıysa → `{}`. Araç yok / timeout / başarısız → **`{"route_flag": "native"}`** (native fallback **done**: Ghidra koruyucusu geçer, analiz Ghidra ile sürer) |
| `unpack_dotnet_node` | **done (araçlarla doğrulanmadı)** | `sample.route == "dotnet"` ise `de4dot <f> -o <f>.clean` → `ilspycmd <f>.clean` (stdout) → `source_code=[DecompiledFunction(name="dotnet_source", priority=10, ...)]`; `.clean` dosyası işlem sonunda silinir | Rota farklıysa → `{}`. Araç yok / timeout / başarısız → **`{"route_flag": "native"}`** (native fallback **done**) |
| `db_writer_node` | **done** | `db.py` (SQLite): `samples`, `findings`, `functions` (`llm_summary`, `size`, `is_library`, `capa_hits`, `xrefs` dahil), `calls`, `llm_claims`. Liste sütunları JSON olarak yazılır. `ai_supervisor` raporu (`state.analysis_report`) boş değilse `insert_llm_claims` ile `llm_claims`'e yazılır. Yeniden analiz = sha256 için sil-ekle (idempotent). Eski şemalı DB `init_db` ile otomatik `ALTER TABLE` migrasyonuna girer | DB hatası pipeline'ı düşürmez (log). Testler: `tests/test_db.py`, `tests/test_api.py` |
| `main.py` (FastAPI + UI) | **done** | `POST /api/upload` (geçici klasöre kaydet → LangGraph arka planda), `GET /api/samples`, `GET /api/samples/{sha256}` (bulgular, fonksiyonlar, supervisor raporu), `GET /` tek sayfa çevrimdışı UI. Çalıştırma: `python main.py --serve` (veya `uvicorn main:app`). CLI (`python main.py <dosya>`) korunur | Upload boyut sınırı (413), dosya adı temizleme, boş dosya (400), analiz hatası `analysis_status: error`. Testler: `tests/test_api.py` |
| `static_feature_node` | **done** | capa + FLOSS + pefile (`extract_imports`, `section_entropy`, `match_import_combos`). Tüm bulgular **`state.findings`** altında toplanır (`Finding`: source/kind/value/address/confidence; kaynaklar: yara, capa, floss, import_combo, pefile_entropy). `capabilities`, `ghidra_hints`, `extracted_strings` uyumluluk için durur. LLM katmanı kanıtı doğrudan `state.findings`'ten okur. **Eksik:** benign baseline | Araçlar yoksa `findings` boş kalır, akış çökmez. Testler: `tests/test_static_features.py` |
| `deep_inspection_node` | **kod hazır — gerçek Ghidra'da doğrulanmadı** | `run_ghidra(file_path, ghidra_hints, findings)` → `ghidra_input.json` (`hints`, `findings`, `combo_apis`). `export_functions.py` (PyGhidra/Python 3): TÜM fonksiyonlar puanlanır (capa +5, tehlikeli API +4, import combo API'si +4, çok büyük −2, library/thunk 0); en yüksek puanlı ilk 100 decompile edilir (`xrefs`, `decompile_warnings`, `callees` adresleri dolu); doğrudan callee'ler `c_code: ""` ile eklenir (≤500). İpucu/puan yoksa en büyük 20 fonksiyon denenir. **Koruyucu:** `source_code` doluysa veya `route_flag != "native"` ise Ghidra hiç çalıştırılmaz (`{}`) | `functions[]` dolar; capa yoksa da çalışır; LLM katmanı `c_code` boş kayıtları atlar. Testler: `tests/test_export_functions.py` (saf mantık + runner) |
| `ai_extractor/reverser/supervisor` | **kısmi** | `ai_reverser` ve `ai_supervisor` **LLM katmanına bağlandı** (`llm_layer/`). `ai_extractor` deterministik IoC yapıyor. | `docs/LLM-LAYER.md` |

### Altyapı eksikleri
- ~~SQLite/DB yok~~ → **done.** `llm_claims` tablosu eklendi; `functions` tablosundaki eksik sütunlar
  (`llm_summary`, `size`, `is_library`, `capa_hits`, `xrefs`) **giderildi**.
- ~~Native fallback yok~~ → **done** (python/dotnet unpack başarısızlığında `route_flag = "native"`).
- ~~FastAPI/UI yok~~ → **done** (`python main.py --serve`).
- Kalan: `.gitignore` eklendi ama `__pycache__/*.pyc` hâlâ git geçmişinde izleniyor olabilir (`git rm -r --cached __pycache__`); kimlik doğrulama / çok kullanıcılı iş kuyruğu yok (iş durumu bellek içi).

---

## 3. Veri sözleşmesi (KRİTİK — LLM katmanı bunu bekliyor)

Pipeline'ın ürettiği ve LLM katmanının tükettiği yapı:

```jsonc
// AgentState'e eklenmesi/uyumlu olması beklenen alanlar
{
  "sample": {
    "sha256": "...",
    "file_type": "PE|ELF|...",
    "route": "python|dotnet|native|fast_track",
    "packer": "UPX|none|...",
    "arch": "x86-64"
  },

  "findings": [
    {
      "source": "capa|floss|import|ioc|yara|entropy",
      "kind": "capability|string|import_combo|ioc|signature|section",
      "value": "...",
      "address": "0x401000",        // varsa; yoksa null
      "confidence": 0.0             // 0-1; deterministik araçlar için 1.0
    }
  ],

  // Ghidra çıktısı — LLM'in asıl girdisi
  "functions": [
    {
      "offset": "0x140001470",
      "name": "FUN_140001470",
      "priority": 5,                 // capa +5, import combo +4, ioc +3, library/thunk 0
      "c_code": "...",               // ya da c_code_ref (DB)
      "size": 128,
      "is_library": false,
      "callees": ["0x140001010"],    // call graph + bottom-up için ŞART
      "xrefs": ["0x140002000"],      // çağrı yerleri (döngü/koşul bilgisi)
      "decompile_warnings": []       // decompile güveni için
    }
  ],

  "ghidra_hints": [ {"offset": "0x401000", "rule": "..."} ]
}
```

**Neden bu alanlar:** LLM katmanı (a) önceliğe göre bağlam seçecek, (b) bottom-up
özet için `callees` kullanacak, (c) kanıtı `findings`'ten doğrulayacak,
(d) decompile güvenini `decompile_warnings`'ten okuyacak.

---

## 4. Öncelik sırası (öneri)

**P0 — hattı uçtan uca çalıştırır:**
1. `entry_node` (DIE + YARA)
2. `unpack_native_node` (UPX)
3. `static_feature_node`: importlar + entropy + `findings[]`

**P1 — kapsam:**
4. `unpack_python_node`, `unpack_dotnet_node`
5. `deep_inspection_node`: `callees`/`xrefs`/tüm fonksiyonlar + ipucu boşken çalışma

**P2 — ürünleşme:**
6. SQLite şeması + yazma — **done**
7. FastAPI/UI — **done**
8. `.gitignore` — done; `__pycache__` git'ten çıkarma (`git rm -r --cached`) — açık

---

## 5. Bilinen tuzaklar

1. **PyGhidra:** `export_functions.py` artık Python 3 / PyGhidra için yazıldı
   (Jython değil). Ghidra 12'de `analyzeHeadless -postScript` ile `.py` betiğinin
   PyGhidra modunda çalıştığı bir kurulumda **doğrulanmalı**; `ghidra_runner.py`
   komutu standart `analyzeHeadless` biçiminde bırakıldı.
2. **JDK:** `analyzeHeadless` için gerçek JDK 21+ şart (`JAVA_HOME`).
3. **Araç yokluğu:** `capa`/`floss`/`diec`/`yara` kurulu değilse düğümler
   **çökmemeli**; boş sonuç + log ile devam etmeli (mevcut kod bunu yapıyor).
4. **Büyük binary:** 180 MB Godot exe'de 215k fonksiyon raporlandı; timeout +
   öncelik olmadan Ghidra pahalı. `-analysisTimeoutPerFile` ve erişilebilirlik filtresi kullan.
5. **Testler:** yeni saf mantık için `tests/`'e birim test ekle (mevcut desen).

---

## 6. Tanım-of-done (pipeline)

- [ ] Bir örnek verildiğinde `entry → unpack → static_feature → deep_inspection`
      zinciri **çökmeden** çalışır.
- [ ] `state` içinde `sample`, `findings`, `functions` (sözleşmeye uygun) dolar.
- [ ] Araçlardan biri yoksa akış devam eder, log'a yazar.
- [ ] `pytest` geçer.
- [ ] Yeni eklenen saf mantık test edilmiş.

---

## 7. İletişim
- LLM katmanı ayrı kişide; **bu sözleşme değişirse haber ver**.
- Ortak dosyalar: `state.py`, `nodes.py`. Aynı anda düzenlemeyin; küçük PR'lar.

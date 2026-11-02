# CrowbarAF — Pipeline Devir Belgesi (LLM katmanına kadar)

Bu belge, CrowbarAF'ın **LLM katmanına kadar** olan kısmında ne olduğunu, ne
kaldığını ve **LLM katmanının beklediği veri sözleşmesini** tanımlar.

> LLM katmanı (ai_* düğümleri, context paketleme, kanıt doğrulayıcı) ayrı bir
> kişide. Bu belgedeki **veri sözleşmesi** doldurulduğu anda iki taraf paralel
> çalışabilir.

---

## 1. Mevcut durum (Adım 1–7 sonrası; `pytest`: 680 geçti, 8 POSIX-izin testi Windows'ta atlanır)

> Bu belge güncel tutuluyor. Önceki "eksikler" listesinin tamamı **done** (bkz. §8).
> Yeni bölümler: §2b (split mod + `validate_state.py`), §2c (otorite katmanları / Policy C),
> §2d (bulgu bütünlüğü: `finding_id` + `verified`).

### Çalışan / hazır
| Dosya | İçerik |
|---|---|
| `state.py` | `AgentState`, `SampleInfo` (`sample`), `DecompiledFunction`, `ghidra_hints` |
| `graph.py` | LangGraph iskeleti + koşullu yönlendirme (`route_after_entry`) |
| `nodes.py` | `entry_node`, `unpack_native_node`, `compute_sha256`, `run_die`, `run_yara`, `decide_route`, `filter_iocs`, `summarize_capa`, `extract_ghidra_hints`, `run_floss`, `run_capa`, `deep_inspection_node` |
| `ghidra_runner.py` | `analyzeHeadless` orkestrasyonu, timeout, temp temizliği (`ghidra_input.json`: hints + findings + combo_apis) |
| `export_functions.py` | Ghidra postScript (PyGhidra/Python 3): tüm fonksiyonları puanlar, Top-100'ü decompile eder |
| `import_combos.py` | Import kombinasyon kuralları (`nodes.py` ve `ghidra_runner.py` ortak) |
| `db.py` | SQLite şeması + yazma/okuma; `save_analysis(state)` tek çağrıyla her şeyi yazar (tam hat ve split mod ortak); okuma yolu IoC'leri defang eder |
| `main.py` | FastAPI + çevrimdışı UI + CLI (`--no-llm`, `--no-db`, `--out`, `--serve`) |
| `host_analyze.py` | **Split mod host tarafı:** state.json → LLM + politika + rapor; `--db [PATH]` ile SQLite'a yazar |
| `sandbox/` | `run_offline_analysis.sh`, `run_host_analysis.sh`, `validate_state.py` (gümrük aracı), `README.md` |
| `utils.py` | `defang_ioc` / `defang_text` / `defang_finding` (analist güvenliği) |
| `report.py` | Araç-öncelikli rapor (md/html/json); IoC'ler defang edilir, `verified=False` bulgular `(Unverified)` ile işaretlenir |
| `llm_layer/` | LLM katmanı: bağlam seçimi, özetleme, `verdict.py` (dört durumlu karar, otorite katmanları, Policy C) — bkz. `docs/LLM-LAYER.md` |
| `tests/` | `test_nodes`, `test_entry_node`, `test_unpack_nodes`, `test_static_features`, `test_export_functions`, `test_db`, `test_api`, `test_split_mode`, `test_validate_state`, `test_defang`, `test_verdict`, `test_report`, `test_llm_layer` |

### Doğrulanmış teknik notlar
- Ghidra **12.1.4 + JDK** gerekiyor; JRE yetmiyor.
- Ghidra 12'de **Jython varsayılan değil**; `export_functions.py` bu yüzden
  PyGhidra / Python 3'e taşındı (bkz. §5 tuzak 1).
- `.gitignore` var (`__pycache__/`, `*.pyc`, `.venv/`, `.env`, `runs/`, `*.db`, `reports/`); `git ls-files`
  artık hiç `.pyc` izlemiyor.
- Gerçek Ghidra 12.1.4 ile uçtan uca doğrulandı (IoC xref, decoded-string xref, UPX açma); gerçek ELF/`readelf`
  çıktısı ve UI'ın tarayıcıda görsel doğrulaması **yapılmadı** (testler mock/fake ile).

---

## 2. Eksikler — düğüm bazında

| Düğüm | Durum | Yapılacak | Kabul kriteri |
|---|---|---|---|
| `entry_node` | **done** | SHA-256 (`compute_sha256`) + `diec --json` (`run_die`) + YARA (`run_yara`, `yara-python`/kural dizini yoksa `[]`) + `decide_route`. Çıktı: `sample` (`sha256`, `file_type`, `arch`, `packer`, `route`), `route_flag`, `yara_results` | Araç yoksa çökmez; `sample` varsayılanları (`"unknown"`) korunur, `route_flag` yine belirlenir. Testler: `tests/test_entry_node.py` |
| `unpack_native_node` | **done (UPX)** | `sample.packer` içinde `upx` varsa `upx -d -o <file>.unpacked <file>`; başarılıysa `file_path` açılmış dosyaya güncellenir (`sample.sha256` orijinal kalır). UPX dışı packer'lar (ASPack, Themida vb.) **yok** | UPX değilse / `upx` yok / timeout / bozuk başlık → `{}` (orijinal dosyayla devam) |
| `unpack_python_node` | **done (araçlarla doğrulanmadı)** | `sample.route == "python"` ise `pyinstxtractor` (geçici dizinde) → ana `.pyc` (exe adı / "Possible entry point" / en büyük) → `pycdc`, olmazsa `decompyle3`. Çıktı: `source_code=[DecompiledFunction(name="main_script", priority=10, c_code=...)]` | Rota farklıysa → `{}`. Araç yok / timeout / başarısız → **`{"route_flag": "native"}`** (native fallback **done**: Ghidra koruyucusu geçer, analiz Ghidra ile sürer) |
| `unpack_dotnet_node` | **done (araçlarla doğrulanmadı)** | `sample.route == "dotnet"` ise `de4dot <f> -o <f>.clean` → `ilspycmd <f>.clean` (stdout) → `source_code=[DecompiledFunction(name="dotnet_source", priority=10, ...)]`; `.clean` dosyası işlem sonunda silinir | Rota farklıysa → `{}`. Araç yok / timeout / başarısız → **`{"route_flag": "native"}`** (native fallback **done**) |
| `db_writer_node` | **done** | `db.py` (SQLite; yazma tek noktadan `db.save_analysis(state)`, split modda `host_analyze.py --db` ile ortak): `samples`, `findings` (`finding_id`, `verified` dahil; eski DB'ler `ALTER TABLE`, eski satırlar `verified=1`), `functions` (`llm_summary`, `size`, `is_library`, `capa_hits`, `xrefs`, `iocs` dahil; `iocs` JSON listesi, eski DB'ler `ALTER TABLE` ile yükseltilir), `calls`, `llm_claims`. Liste sütunları JSON olarak yazılır. `ai_supervisor` raporu (`state.analysis_report`) ve/veya dosya kararı (`state.verdict`, JSON) doluysa `insert_llm_claims` ile `llm_claims` (`supervisor_report`, `verdict`) tablosuna yazılır; fonksiyon başına `llm_summary` `functions.llm_summary`'ye gider. `get_all_samples`/`get_sample_details` ve API `verdict`'i ayrıştırılmış dict olarak döndürür; UI karar rozetini (malicious/needs_review/unknown/no_evidence) gösterir. Yeniden analiz = sha256 için sil-ekle (idempotent). Eski şemalı DB `init_db` ile otomatik `ALTER TABLE` migrasyonuna girer | DB hatası pipeline'ı düşürmez (log). Testler: `tests/test_db.py`, `tests/test_api.py` |
| `main.py` (FastAPI + UI) | **done** | `POST /api/upload` (geçici klasöre kaydet → LangGraph arka planda), `GET /api/samples`, `GET /api/samples/{sha256}` (bulgular, fonksiyonlar, supervisor raporu), `GET /` tek sayfa çevrimdışı UI. Çalıştırma: `python main.py --serve` (veya `uvicorn main:app`). CLI (`python main.py <dosya>`) korunur | Upload boyut sınırı (413), dosya adı temizleme, boş dosya (400), analiz hatası `analysis_status: error`. Testler: `tests/test_api.py` |
| `static_feature_node` | **done** | capa + FLOSS + pefile (`extract_imports`, `section_entropy`, `match_import_combos`). Tüm bulgular **`state.findings`** altında toplanır (`Finding`: source/kind/value/address/confidence; kaynaklar: yara, capa, floss, import_combo, pefile_entropy). Ham import listesi **bulgu olmaz** (gürültü); yalnızca `match_import_combos` ve imphash için kullanılır: PE → pefile, ELF (`\x7fELF`) → `readelf --wide --dyn-syms` (UND FUNC; `readelf` yoksa `[]`). LLM'e sadece eşleşen combolar (`import_combo`; PE + `Linux Process Injection`/`Linux Evasion`) ve `Finding(source="imphash", kind="grouping_key")` gider (PE: `pe.get_imphash()`, ELF: MD5 of `",".join(imports)`). PE metadata (`source="pe_metadata"`; dosya pefile ile tek kez yüklenir): `authenticode` (`Present (Unverified)`, yalnızca varlık, doğrulama yok), `version_info` (OriginalFilename/CompanyName/FileDescription/LegalCopyright/ProductName/FileVersion, `; ` ile tek satır, değer başına ≤200 karakter), `manifest_privilege` (yalnızca asInvoker/highestAvailable/requireAdministrator). Section entropy ELF'i de kapsar (`readelf -S -W` + dosyadan bayt okuma; kaynak `elf_entropy`, PE için `pefile_entropy`; eşik > 7.0). `capabilities`, `ghidra_hints`, `extracted_strings` uyumluluk için durur. LLM katmanı kanıtı doğrudan `state.findings`'ten okur. **TLSH** (`compute_tlsh`, `py-tlsh` opsiyonel; dosya < 50 bayt veya kütüphane yoksa `""`): `Finding(source="tlsh", kind="grouping_key")`. **Araç profili** `CROWBAR_TOOL_PROFILE=core\|deep` (varsayılan `deep`): `core`'da capa + FLOSS atlanır (`deep_inspection_node` de Ghidra'yı çalıştırmaz); DIE, YARA, pefile/readelf, unpacker'lar ve TLSH her profilde çalışır. **Bulgu bütünlüğü (§2d):** düğüm sonunda her bulguya `finding_id` atanır ve FLOSS'un statik ip/url/domain/email string'leri dosya byte'larında (UTF-8/UTF-16LE) aranır; bulunamazsa `verified=False`. capa'nın anlamsız `contain loop` kuralı bulgulardan ve öncelikten elenir; FLOSS statik string'leri de IoC havuzuna girer. **Açık:** benign baseline; araç başına "unique contribution" ölçümü | Araçlar yoksa `findings` boş kalır, akış çökmez. Testler: `tests/test_static_features.py` |
| `deep_inspection_node` | **kod hazır — gerçek Ghidra'da doğrulanmadı** | `run_ghidra(file_path, ghidra_hints, findings)` → `ghidra_input.json` (`hints`, `findings`, `combo_apis`). `export_functions.py` (PyGhidra/Python 3): TÜM fonksiyonlar puanlanır (capa +5, tehlikeli API +4, import combo API'si +4, IoC string referansı +3, çok büyük −2, **kütüphane/stub = 0**); **kütüphane sezgisi (`is_library_heuristic`, done):** `isThunk()`/`isExternal()`, ad önekleri (`__libc_`, `_Z`, `std::`, `__cxa_`, `__gxx_`, `j_`, `CRT_`, `golang.`, `runtime.`) veya `size < 16` ⇒ `is_library=True`, `priority=0`, Top-N'e girmez (istisna: entry/main ve capa/IoC kanıtı taşıyan fonksiyonlar ad/boyut sezgisiyle kütüphane sayılmaz; Ghidra thunk/external bayrağı kesin); FLOSS decoded/tight/stack string'leri `decoded_hints` ile fonksiyona bağlanır (+3, `iocs`, çağıran 1 hop); **adressiz string → fonksiyon eşleme (done)**: findings'teki `ip/url/domain/registry/file/email` değerleri tanımlı string'lerde aranır (eşit veya içeren, büyük/küçük harf duyarsız), string'e referans veren fonksiyonun `iocs` listesine yazılır ve fonksiyon +3 alır (fonksiyon başına bir kez); en yüksek puanlı ilk 100 decompile edilir (`xrefs`, `decompile_warnings`, `callees` adresleri dolu); doğrudan callee'ler `c_code: ""` ile eklenir (≤500). İpucu/puan yoksa en büyük 20 fonksiyon denenir. **Koruyucu:** `CROWBAR_TOOL_PROFILE=core` ise, `source_code` doluysa veya `route_flag != "native"` ise Ghidra hiç çalıştırılmaz (`{}`) | `functions[]` dolar; capa yoksa da çalışır; LLM katmanı `c_code` boş kayıtları atlar. Testler: `tests/test_export_functions.py` (saf mantık + runner) |
| `ai_extractor/reverser/supervisor` | **kısmi** | `ai_reverser` ve `ai_supervisor` **LLM katmanına bağlandı** (`llm_layer/`). `ai_extractor` deterministik IoC yapıyor. | `docs/LLM-LAYER.md` |

### Altyapı eksikleri
- ~~SQLite/DB yok~~ → **done.** `llm_claims` tablosu eklendi; `functions` tablosundaki eksik sütunlar
  (`llm_summary`, `size`, `is_library`, `capa_hits`, `xrefs`) **giderildi**; `functions.iocs` sütunu da eklendi (Adım 5).
- ~~Native fallback yok~~ → **done** (python/dotnet unpack başarısızlığında `route_flag = "native"`).
- ~~FastAPI/UI yok~~ → **done** (`python main.py --serve`).
- ~~`__pycache__` git'te~~ → **done** (`git ls-files` temiz).
- Kalan (bilinçli kapsam dışı): kimlik doğrulama / çok kullanıcılı iş kuyruğu yok (iş durumu bellek içi).

---

## 2b. Split mod (VM / host ayrımı) — **done**

Gerçek zararlıya dokunan deterministik araçlar **offline VM**'de, LLM çağrıları **host**'ta çalışır.
API anahtarı VM'e hiç girmez.

```text
Offline VM:  main.py <örnek> --no-llm --no-db --out state.json     (anahtar yok, ağ yok, örnek çalıştırılmaz)
   │  yalnızca state.json (tek yönlü)
   ▼
Gümrük:      sandbox/validate_state.py state.json                  (VM çıktısı: --allow-empty-summaries)
   ▼
Host:        host_analyze.py --state state.json --out state_llm.json [--db [PATH]]
             (LLM + Policy C + rapor; anahtar yalnızca host ortamında)
```

- `main.py --no-llm/--no-db` ≡ `CROWBAR_SKIP_LLM=1` / `CROWBAR_SKIP_DB=1`; `ai_reverser` ve `db_writer` `{}` döner.
- `host_analyze.py` state'i güvenilmez girdi sayar (boyut sınırı + Pydantic doğrulaması); `CROWBAR_SKIP_LLM`
  host'ta açıksa reddeder. `--db [PATH]` (varsayılan `crowbaraf.db` / `CROWBAR_DB_PATH`) verilirse
  `db.save_analysis` ile sample, bulgular (`finding_id`/`verified`), fonksiyonlar (`llm_summary` dahil),
  `llm_claims` (rapor + `verdict`) yazılır; böylece split moddaki sonuçlar UI'da da görünür. DB hatası
  `--out` dosyasını kaybettirmez (çıkış kodu 1).
- **`sandbox/validate_state.py` (gümrük aracı).** Çıkış 0 = geçerli, 1 = reddedildi. Kontroller, sırayla:
  1. **boyut** ≤ 50 MB (`--max-mb`; okumadan önce);
  2. **şema**: `sample`, `route_flag`, `file_path` + tip kontrolleri;
  3. **POSIX izni**: `0o600` dışında bit varsa red (Windows'ta atlanır ve "skipped" yazılır);
  4. **`llm_summary`**: her fonksiyonda string, boş olmamalı (yarım analiz). Deterministik VM state'i bilerek
     boştur → `--allow-empty-summaries`; string tip kontrolü yine geçerlidir;
  5. **anahtar sızıntısı**: iç içe tüm string'ler ve sözlük anahtarlarında `sk-…` (≥16 anahtar karakteri, kelime
     başı) veya `CROWBAR_LLM_API_KEY` değeri; eşleşen sır **hiç yazdırılmaz**, yalnızca JSON yolu.
  Diğer kontroller başarısız olsa bile anahtar taraması çalışır. Testler: `tests/test_validate_state.py`.
- Windows notu: `chmod` etkisizdir; izin kontrolü ve `0o600` testleri yalnızca POSIX'te çalışır. `sandbox/*.sh`
  bash'tir (VM/WSL).
- Kapsam dışı: gerçek zararlı batch'i, bulut API koşuları, etik/legal onay (bkz. `docs/HANDOFF-*.md`).

## 2c. Otorite katmanları ve Policy C (iki sinyal) — **done**

Kaynak: `llm_layer/verdict.py`. Karar durumları: `malicious` / `needs_review` / `unknown` / `no_evidence`
(asla "clean").

| Kaynak | Otorite | Karar katkısı |
|---|---|---|
| YARA | yüksek | sinyal `yara` |
| FLOSS C2-benzeri URL/IP | düşük (kritik) | sinyal `c2` |
| capa / import combo / yüksek güvenli IoC | orta | sinyal `capa` / `import_combo` / `ioc` (en fazla `needs_review`) |
| LLM şüpheli fonksiyon | — | sinyal `llm` |
| imphash, TLSH, entropy, pe_metadata | — | karar kanıtı değil (gruplama/bağlam) |

**Policy C:** `malicious` için **en az iki bağımsız sinyal sınıfı** ve en az biri güçlü (`llm`/`yara`/`c2`) gerekir.
Tek güçlü sinyal (yalnızca YARA, yalnızca LLM, yalnızca C2) → `needs_review`. Kapatma:
`CROWBAR_TWO_SIGNAL_MALICIOUS=0` (veya `compute_verdict(require_two_signals=False)`).
`is_critical_finding` (must-include/fail-closed): YARA + yüksek IoC + C2; trivial capa (`contain loop`) filtrelenir.
Fail-closed: LLM "benign" derse ve ilgili kritik bulgu varsa fonksiyon `unknown` olur.

## 2d. Bulgu bütünlüğü: `finding_id` + `verified` — **done**

- `Finding.finding_id` = `md5(f"{source}_{kind}_{value}_{address}")[:8]`; `static_feature_node` tüm bulgulara
  (yara dahil) atar; DB'ye, API'ye ve verdict çıktısına (`id`) aynı kimlik gider.
- `Finding.verified` (varsayılan `True`): FLOSS'un **statik** `ip/url/domain/email` string'i dosyanın raw
  byte'larında (UTF-8 veya UTF-16LE; tek `mmap` geçişi) bulunamazsa `False`. FLOSS decoded/tight/stack
  string'leri (`floss_hints`) ve diğer türler (registry/file/yara/capa/…) kontrol edilemez → `True` kalır;
  `False` olan bir bulgu bir daha `True` yapılmaz. Dosya okunamazsa hiçbir bulgu işaretlenmez. Üst sınır: 500 tekil değer.
- **Otorite kaybı:** `verified=False` kritik bulgu sinyal sayılmaz → tek başına veya başka sinyali destekleyerek
  `malicious` üretemez; yalnızca `needs_review` (ve `unknown`/`no_evidence`'ı `needs_review`'a yükseltir).
  LLM "temiz" dese bile fail-closed geçerlidir. Çıktı: `counts.unverified_critical`, `unverified_findings`.
- UI ve `report.py`: `verified=False` bulgunun yanında **(Unverified)** uyarısı.
- Güvenlik: IoC'ler API/rapor çıktısında **defang** edilir (`hxxp://`, `host[.]tld`); DB ve state'te ham kalır.

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
      "source": "yara|capa|floss|import_combo|imphash|tlsh|pe_metadata|pefile_entropy|elf_entropy",
      "kind": "rule|attack|behavior|url|ip|registry|file|grouping_key|authenticode|version_info|manifest_privilege|high_entropy",
      "value": "...",
      "address": "0x401000",        // varsa; yoksa "" (state) / null (llm_layer)
      "confidence": 0.0,            // 0-1; deterministik araçlar için 1.0
      "finding_id": "a1b2c3d4",     // md5(source_kind_value_address)[:8]
      "verified": true              // false: statik metin IoC'si dosya byte'larında yok (§2d)
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
      "iocs": ["http://c2.example/gate.php"],  // bu fonksiyonun string referansıyla kullandığı IoC'ler (Ghidra)
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
8. `.gitignore` — **done**; `__pycache__` git'ten çıkarıldı — **done**
9. Split mod + `validate_state.py` — **done**; otorite katmanları / Policy C — **done**; bulgu bütünlüğü — **done**

---

## 5. Bilinen tuzaklar

1. **PyGhidra (doğrulandı + çözüldü):** `export_functions.py` Python 3 / PyGhidra
   için yazıldı. Düz `analyzeHeadless -postScript export_functions.py` ile
   **çalışmaz**: `ERROR: Ghidra was not started with PyGhidra. Python is not
   available` → 0 fonksiyon. `ghidra_runner.py` artık AnalyzeHeadless'i
   `pyghidra_launcher.py <ghidra> -H --console ...` ile başlatıyor (Ghidra
   12.1.4'te doğrulandı: 16 fonksiyon, `c_code`/`callees`/`size` dolu).
   **Gereksinim:** `pyghidra` Python ortamında kurulu olmalı; Ghidra içindeki
   wheel'den:
   `pip install --no-index -f <ghidra>/Ghidra/Features/PyGhidra/pypkg/dist pyghidra`.
   Kurulu değilse launcher etkileşimli "install?" sorar ve etkileşimsiz çalışmada patlar.
2. **JDK:** `analyzeHeadless` için gerçek JDK 21+ şart (`JAVA_HOME`).
3. **Araç yokluğu:** `capa`/`floss`/`diec`/`yara` kurulu değilse düğümler
   **çökmemeli**; boş sonuç + log ile devam etmeli (mevcut kod bunu yapıyor).
4. **Büyük binary:** 180 MB Godot exe'de 215k fonksiyon raporlandı; timeout +
   öncelik olmadan Ghidra pahalı. `-analysisTimeoutPerFile` ve erişilebilirlik filtresi kullan.
5. **Testler:** yeni saf mantık için `tests/`'e birim test ekle (mevcut desen).

---

## 6. Tanım-of-done (pipeline)

- [x] Bir örnek verildiğinde `entry → unpack → static_feature → deep_inspection`
      zinciri **çökmeden** çalışır (gerçek Ghidra 12.1.4 ile doğrulandı; python/dotnet unpack araçlarıyla doğrulanmadı).
- [x] `state` içinde `sample`, `findings`, `functions` (sözleşmeye uygun) dolar.
- [x] Araçlardan biri yoksa akış devam eder, log'a yazar.
- [x] `pytest` geçer (680 geçti, 8 POSIX-only atlandı).
- [x] Yeni eklenen saf mantık test edilmiş.

---

## 7. İletişim
- LLM katmanı ayrı kişide; **bu sözleşme değişirse haber ver**.
- Ortak dosyalar: `state.py`, `nodes.py`. Aynı anda düzenlemeyin; küçük PR'lar.

---

## 8. Eylem planı durumu (Adım 1–7)

| # | İş | Durum |
|---|---|---|
| 1 | Test onarımı (Windows POSIX izin assert'i atlanır) | **done** |
| 2 | Split mod kalıcılığı (`host_analyze.py --db`, `db.save_analysis`) + IoC defanging (`utils.py`, API, `report.py`) | **done** |
| 3 | State doğrulama aracı (`sandbox/validate_state.py` + testler) | **done** |
| 4 | Kütüphane fonksiyonu sezgisi (`export_functions.is_library_heuristic`) | **done** (FID/BSim hariç, bkz. `TOOL-ADDITIONS.md` §2.2) |
| 5 | TLSH + `CROWBAR_TOOL_PROFILE=core\|deep` | **done** |
| 6 | Araç çıktısı bütünlüğü (`finding_id`, `verified`) ve otorite politikası | **done** |
| 7 | Dokümantasyon senkronu + `(Unverified)` UX | **done** |

**Bilinçli olarak açık kalanlar** (kod değil, doğrulama/kapsam):
- Gerçek ELF/`readelf` çıktısı ve UI'ın tarayıcıda görsel doğrulaması yapılmadı (mock/fake testler).
- Authenticode yalnızca **varlık** (doğrulama yok, `osslsigncode` yok); Ghidra FID/BSim yok; TLSH benzerlik karşılaştırması yok.
- Araç başına "unique contribution" ölçümü ve benign baseline yok.
- `verified` yalnızca FLOSS statik IoC'leri için; capa/YARA için araç-çıktısı hash'i ve tool-version kaydı yok (bkz. `EVIDENCE-CHANNEL.md` §3).
- Gerçek zararlı batch'i, bulut API koşuları ve etik/legal onay bu belgenin kapsamı dışında (`docs/HANDOFF-FULL-STUDY.md`).

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
| `state.py` | `AgentState`, `DecompiledFunction`, `ghidra_hints` |
| `graph.py` | LangGraph iskeleti + koşullu yönlendirme (`route_after_entry`) |
| `nodes.py` | `decide_route`, `filter_iocs`, `summarize_capa`, `extract_ghidra_hints`, `run_floss`, `run_capa`, `deep_inspection_node` |
| `ghidra_runner.py` | `analyzeHeadless` orkestrasyonu, timeout, temp temizliği |
| `export_functions.py` | Ghidra postScript (capa adreslerini decompile eder) |
| `tests/test_nodes.py` | 53 test (saf mantık) — geçiyor |

### Doğrulanmış teknik notlar
- Ghidra **12.1.4 + JDK** gerekiyor; JRE yetmiyor.
- Ghidra 12'de **Jython varsayılan değil** (ayrı eklenti). `export_functions.py`
  şu an Jython; **PyGhidra/Java'ya taşınmalı** ya da Jython eklentisi kurulmalı.
- `.pyc`/`__pycache__` commit'lenmiş; `.gitignore` yok.

---

## 2. Eksikler — düğüm bazında

| Düğüm | Durum | Yapılacak | Kabul kriteri |
|---|---|---|---|
| `entry_node` | **stub** | `diec --json` → `file_metadata`; YARA → `yara_results`; `decide_route` | Bir PE/ELF'de dil/derleyici/mimari/packer dolar; araç yoksa çökmez, `route_flag` yine belirlenir |
| `unpack_native_node` | **stub** | Packer'a göre UPX `-d` vb.; `file_path`'i açılmış dosyaya güncelle | UPX'li örnekte unpack olur, sonraki düğümler açılmış dosyayı kullanır; olmazsa graceful fallback |
| `unpack_python_node` | **stub** | `pyinstxtractor` → `.pyc`; sürüme göre `pycdc`/`decompyle3` | PyInstaller exe'sinden `.py` kaynağı çıkar; başarısızsa "kaynak çıkarılamadı" + native fallback |
| `unpack_dotnet_node` | **stub** | `de4dot` + `ilspycmd` | .NET assembly'den `.cs` çıkar; hata toleranslı |
| `static_feature_node` | **kısmi** | capa/FLOSS var; **pefile importları**, **section entropy**, **import kombinasyon kuralları**, **benign baseline**, **fonksiyon önceliği** ekle | `findings[]` dolar (source/kind/value/address/confidence); capa adresleri korunur |
| `deep_inspection_node` | **kısmi** | Tüm erişilebilir fonksiyonları decompile et; **`callees`/`xrefs`/`size`/`is_library`/`decompile_warnings`** ekle; **ipucu boşken de çalış** | `functions[]` dolar; çağrı grafiği kurulabilir; capa yoksa bile çalışır |
| `ai_extractor/reverser/supervisor` | **kısmi** | `ai_reverser` ve `ai_supervisor` **LLM katmanına bağlandı** (`llm_layer/`). `ai_extractor` deterministik IoC yapıyor. | `docs/LLM-LAYER.md` |

### Altyapı eksikleri
- **SQLite/DB yok** (roadmap'te var): `samples`, `findings`, `functions`, `calls`, `llm_claims`.
- **FastAPI/UI yok** (roadmap'te var).
- `.gitignore` yok; `__pycache__` repoda.

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
6. SQLite şeması + yazma
7. FastAPI/UI
8. `.gitignore` + `__pycache__` temizliği

---

## 5. Bilinen tuzaklar

1. **Jython:** Ghidra 12'de `export_functions.py` çalışmaz (Jython eklentisi yok).
   PyGhidra/Java'ya taşı veya eklentiyi kur.
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

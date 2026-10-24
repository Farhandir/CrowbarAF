# Araç Ekleme Rehberi — Kategori 1 & 2

Bu belge, analiz hattına eklenecek yeni araçların **nasıl kullanılacağını,
nereye bağlanacağını ve kabul kriterlerini** tanımlar.

## 0. İlke
- **Ham çıktı ≠ rapor.** Araç çıktısı `findings`'e yazılır; rapor onu damıtır.
- **Unique contribution testi:** Bir araç ancak *"kapalıyken kaçırılan, açıkken
  yakalanan benzersiz bulgu > 0"* ise eklenir. YARA-X / rizin bu testi geçmiyor → eklenmez.
- **Core / deep:** `CROWBAR_TOOL_PROFILE=core|deep` (varsayılan `core`).
  - core: DIE, YARA, capa, FLOSS, import (PE+ELF), entropy, Ghidra
  - deep: + Authenticode, kaynaklar, imphash, TLSH, FLIRT
- **Kademeli bozulma:** Araç yoksa/hata verirse **çökme**; boş sonuç + log.

## 1. Ortak kurallar
Her araç `state.Finding` üretir:
```python
Finding(source="...", kind="...", value="...", address="", confidence=1.0)
```
- `static_feature_node` içinde çağrılır, `build_findings`/`merge_findings` ile birleştirilir.
- Her araç için `tests/test_static_features.py` deseninde **birim test** (mock çıktı).
- `_run_tool(cmd, timeout)` yardımcısını kullan (zaman aşımı + hata toleransı).

---

## Kategori 1 — Benzersiz kanıt

### 1.1 ELF importları (`readelf`)
**Neden:** Şu an `extract_imports` yalnızca `pefile` (PE). ELF'te boş dönüyor; import
kombinasyon kuralları ELF'te hiç çalışmıyor.

**Komut:**
```bash
readelf --wide --dyn-syms <file>    # UND semboller = import edilen fonksiyonlar
readelf -d <file>                   # NEEDED = bağımlı kütüphaneler
```
**Entegrasyon:** `extract_imports(file_path)` içinde:
- PE ise mevcut `pefile` yolu,
- ELF ise `readelf` çıktısını ayrıştır (`UND` satırlarındaki isimler).

**Finding:**
```python
Finding(source="import", kind="elf_import", value="connect")
Finding(source="import", kind="elf_library", value="libc.so.6")
```
**Kabul:** ELF örnekte import listesi dolu; `match_import_combos` çalışıyor;
`readelf` yoksa `[]` + log.

### 1.2 PE kaynak / versiyon / manifest (`pefile`)
**Neden:** Sahte isim, sürüm, ikon, manifest — başka araçtan çıkmaz.

**Kullanım:** `pefile` zaten bağımlılık.
```python
pe = pefile.PE(path, fast_load=True)
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
# Versiyon: pe.FileInfo -> StringFileInfo (CompanyName, ProductName, FileVersion, OriginalFilename)
# Manifest: RT_MANIFEST kaynağı (varsa XML)
```
**Finding:**
```python
Finding(source="pefile", kind="version_info", value="CompanyName=Foo;FileVersion=1.2.3")
Finding(source="pefile", kind="manifest", value="requireAdministrator")
Finding(source="pefile", kind="resource_lang", value="tr-TR")
```
**Kabul:** PE'de versiyon/manifest bulguları dolu; ELF'te atlanır.

### 1.3 Authenticode / imza
**Neden:** "İmzalı mı, geçerli mi, kim imzalamış" — güçlü triyaj sinyali.

**Adım 1 (ucuz):** `pefile` ile sertifika tablosu var mı:
```python
has_sig = hasattr(pe, "DIRECTORY_ENTRY_SECURITY")
```
**Adım 2 (doğrulama):** `osslsigncode` (apt: `sudo apt install osslsigncode`)
```bash
osslsigncode verify -in <file>
```
**Finding:**
```python
Finding(source="signature", kind="present", value="no")          # veya "yes"
Finding(source="signature", kind="valid", value="invalid")       # osslsigncode varsa
Finding(source="signature", kind="signer", value="CN=...")
```
**Kabul:** İmzasız PE'de `present=no`; imzalıysa doğrulama sonucu. `osslsigncode`
yoksa yalnızca "var/yok" (adım 1).

### 1.4 TLSH / ssdeep (fuzzy hash)
**Neden:** Örnekler arası benzerlik; aile/kümeleme/decoy analizi. Tek örnekte anlamsız
→ **korpus gelince** anlam kazanır.

**Kurulum:** `pip install py-tlsh` (veya `ssdeep`)
```python
import tlsh
digest = tlsh.hash(open(path, "rb").read())   # "T1..."
```
**Finding:**
```python
Finding(source="tlsh", kind="fuzzy_hash", value=digest)
```
**Kabul:** Hash üretilir; DB'de saklanır; benzerlik karşılaştırması (opsiyonel) ayrı adım.

---

## Kategori 2 — Türev / yardımcı

### 2.1 imphash
**Neden:** Importlardan türeyen **aile gruplama anahtarı** (yeni bulgu değil).

**Kullanım:** PE: `pe.get_imphash()`. ELF: sıralı import listesinin SHA-256'sı.
```python
Finding(source="imphash", kind="grouping_key", value=imphash)
```
**Kabul:** PE'de standart imphash; ELF'te deterministik türev.

### 2.2 FLIRT / BSim (kütüphane fonksiyonu tanıma)
**Neden:** Kütüphane/thunk fonksiyonlarını atlayıp **context'i küçültmek** (tezin konusu).
Bulgu eklemez, gürültüyü azaltır.

**Aşamalı yol:**
1. **Ucuz heuristic (hemen):** isim önekleri (`__libc_`, `_Z`, `std::`, `operator`),
   `isThunk()`, çok küçük fonksiyonlar, Ghidra'nın "Library" işaretleri.
2. **Ghidra FID / BSim (sonra):** FID veritabanı veya BSim imzaları ile eşleştirme.

**Entegrasyon:** `export_functions.py` zaten `is_library` üretiyor; heuristic'i genişlet.
LLM katmanı `is_library=True` olanları atlıyor.
**Kabul:** Kütüphane fonksiyonu oranı ölçülür; LLM'e giden fonksiyon sayısı düşer.

### 2.3 Section entropy (ELF)
**Neden:** Packed/şifreli bölüm sinyali; capa/Ghidra'nın kör olduğu yeri işaretler.

**Mevcut:** `section_entropy` `pefile` ile PE'de çalışıyor. ELF için `readelf -S`
+ bölüm baytları üzerinden Shannon entropy.
```python
Finding(source="entropy", kind="section", value=".text=7.91")
```
**Kabul:** ELF'te section entropy dolu; yüksek entropy (>7) "packed olabilir" sinyali.

---

## Öncelik ve kabul sırası
| # | Araç | Öncelik | Neden |
|---|---|---|---|
| 1 | ELF importları | **P0** | Gerçek boşluk; kombinasyon kuralları ELF'te çalışmıyor |
| 2 | imphash | **P0** | Ucuz; gruplama anahtarı |
| 3 | PE kaynak/versiyon/manifest | P1 | PE kimlik/aldatma izleri |
| 4 | Authenticode (önce var/yok) | P1 | Güçlü triyaj |
| 5 | Section entropy (ELF) | P1 | Packed sinyali |
| 6 | TLSH | P2 | Korpus gelince |
| 7 | FLIRT/BSim | P2 | Context küçültme; heuristic ile başla |

## Ölçüm: unique contribution
Her araç için:
```
unique(tool) = tool açıkken bulunan benzersiz bulgu
             − diğer araçların da ürettiği
```
`CROWBAR_TOOL_PROFILE` ile aç/kapat, aynı örnek setinde karşılaştır. Yalnızca
`unique > 0` olan araçları `core`'a al.

## Test/DoD
- [ ] Araç yoksa çökmez, `[]` + log.
- [ ] `findings` şemasına uygun kayıt üretir.
- [ ] Birim test (mock çıktı ile) eklenir.
- [ ] `report.py` ilgili bölümü gösterir.
- [ ] `pytest` geçer.

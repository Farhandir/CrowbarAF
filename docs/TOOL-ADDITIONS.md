# Araç Ekleme Rehberi — Kategori 1 & 2

Bu belge, analiz hattına eklenecek yeni araçların **nasıl kullanılacağını,
nereye bağlanacağını ve kabul kriterlerini** tanımlar.

## Durum özeti (güncel)

| # | Madde | Durum | Not |
|---|---|---|---|
| 1.1 | ELF importları (`readelf`) | **done** | `extract_imports` PE+ELF; ham import bulgu olmaz → combo + imphash |
| 1.2 | PE versiyon / manifest | **done** | `source="pe_metadata"` (`version_info`, `manifest_privilege`); kaynak-dil bulgusu yok |
| 1.3 | Authenticode | **done (varlık)** | `Present (Unverified)`; `osslsigncode` doğrulaması **yok** |
| 1.4 | TLSH (fuzzy hash) | **done** | `compute_tlsh`; benzerlik karşılaştırması ayrı adım |
| 2.1 | imphash | **done** | PE: pefile; ELF: MD5(sıralı import listesi) |
| 2.2 | Kütüphane fonksiyonu sezgisi | **done (heuristic)** | `is_library_heuristic`; FID/BSim **yok** |
| 2.3 | ELF section entropy | **done** | `elf_entropy` (`readelf -S -W`) |
| — | `CROWBAR_TOOL_PROFILE=core\|deep` | **done** | varsayılan `deep` |
| — | Unique-contribution ölçümü | **açık** | profil var, ölçüm koşusu yok |

Tüm uygulanan araçlar gerçek ELF/`readelf` ile değil **mock çıktıyla** test edildi; Windows PE dosyaları
(`cmd.exe`) ile PE yolları denendi.

## 0. İlke
- **Ham çıktı ≠ rapor.** Araç çıktısı `findings`'e yazılır; rapor onu damıtır.
- **Unique contribution testi:** Bir araç ancak *"kapalıyken kaçırılan, açıkken
  yakalanan benzersiz bulgu > 0"* ise eklenir. YARA-X / rizin bu testi geçmiyor → eklenmez.
- **Core / deep:** `CROWBAR_TOOL_PROFILE=core|deep` (varsayılan `deep`). **Uygulandı.**
  - core (hızlı tarama): DIE, YARA, unpacker'lar, import (PE+ELF), imphash, entropy,
    PE metadata, TLSH. **capa, FLOSS ve Ghidra atlanır** (`deep_inspection_node` `{}` döner).
  - deep: core + capa + FLOSS + Ghidra (mevcut davranış).
  - Tanınmayan değer uyarıyla `deep` sayılır.
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

**Durum: done.** Uygulanan tasarım yukarıdaki `Finding` örneğinden farklıdır: ham import'lar gürültü olduğu için
**bulgu üretmez**; yalnızca `import_combo` (PE + `Linux Process Injection` / `Linux Evasion`) ve imphash LLM'e gider.
`readelf --wide --dyn-syms` (UND, yalnızca FUNC/IFUNC; timeout 30 sn, `CROWBAR_READELF_TIMEOUT`). `NEEDED`
kütüphane (`elf_library`) bulgusu **yapılmadı**. Statik bağlı ELF'te import yoktur. Gerçek `readelf` ile denenmedi (mock).

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

**Durum: done.** Gerçek şekil: `Finding(source="pe_metadata", kind="version_info", value="OriginalFilename: x; CompanyName: y")`
(tek satır, değer başına ≤200 karakter) ve `kind="manifest_privilege"` (yalnızca `asInvoker` / `highestAvailable` /
`requireAdministrator`; enjeksiyona karşı beyaz liste). Dosya `pefile` ile **bir kez** yüklenir. `resource_lang` yapılmadı.

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

**Durum: done (adım 1 — yalnızca varlık).** Gerçek şekil: `Finding(source="pe_metadata", kind="authenticode",
value="Present (Unverified)")`; imza **doğrulanmaz** (katalog imzalı Windows sistem dosyalarında imza dizini boş
olduğundan "yok" çıkar). Adım 2 (`osslsigncode`) **yapılmadı**.

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
Finding(source="tlsh", kind="grouping_key", value=digest)
```
**Durum: done** (`nodes.compute_tlsh`; her iki profilde çalışır; `py-tlsh` yoksa veya dosya < 50 bayt ise `""`;
`TNULL` da boş sayılır). **Kabul:** Hash üretilir; DB'de saklanır; benzerlik karşılaştırması (opsiyonel) ayrı adım.

---

## Kategori 2 — Türev / yardımcı

### 2.1 imphash
**Neden:** Importlardan türeyen **aile gruplama anahtarı** (yeni bulgu değil).

**Kullanım:** PE: `pe.get_imphash()`. ELF: sıralı import listesinin SHA-256'sı.
```python
Finding(source="imphash", kind="grouping_key", value=imphash)
```
**Kabul:** PE'de standart imphash; ELF'te deterministik türev.

**Durum: done.** ELF türevi SHA-256 değil **MD5(`",".join(sorted(imports))`)**'dır (sıralama, bağlayıcı sırasından
bağımsızlık sağlar). Import yoksa `""`. PE'deki imphash ile ELF'tekiler birbiriyle karşılaştırılamaz.

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

**Durum: adım 1 (heuristic) done; adım 2 (FID/BSim) açık.** `export_functions.is_library_heuristic(func, size)`:
`isThunk()`/`isExternal()`; ad önekleri `__libc_`, `_Z`, `std::`, `__cxa_`, `__gxx_`, `j_`, `CRT_`, `golang.`, `runtime.`;
`size < 16`. `True` ⇒ `is_library=True`, `priority=0`, Top-N'e ve yedek listeye girmez. **İstisna:** entry/main ve
capa/IoC kanıtı taşıyan fonksiyonlar ad/boyut sezgisiyle kütüphane sayılmaz (`SOFT_LIBRARY_REASONS`; `_Z` kullanıcı
C++ kodunu da yakaladığı için); Ghidra thunk/external bayrağı her zaman kesindir. **Ölçüm (oran, LLM'e giden fonksiyon
sayısı) henüz yapılmadı.**

### 2.3 Section entropy (ELF)
**Neden:** Packed/şifreli bölüm sinyali; capa/Ghidra'nın kör olduğu yeri işaretler.

**Mevcut:** `section_entropy` `pefile` ile PE'de çalışıyor. ELF için `readelf -S`
+ bölüm baytları üzerinden Shannon entropy.
```python
Finding(source="entropy", kind="section", value=".text=7.91")
```
**Kabul:** ELF'te section entropy dolu; yüksek entropy (>7) "packed olabilir" sinyali.

**Durum: done.** `Finding(source="elf_entropy", kind="high_entropy", value=".packed: 7.91")` (PE için `pefile_entropy`;
yalnızca eşik > 7.0 üstü bulgu olur). `readelf -S -W` + dosyadan bayt okuma; `readelf` yoksa `{}`.

---

## Öncelik ve kabul sırası
| # | Araç | Öncelik | Neden | Durum |
|---|---|---|---|---|
| 1 | ELF importları | **P0** | Gerçek boşluk; kombinasyon kuralları ELF'te çalışmıyor | **done** |
| 2 | imphash | **P0** | Ucuz; gruplama anahtarı | **done** |
| 3 | PE kaynak/versiyon/manifest | P1 | PE kimlik/aldatma izleri | **done** |
| 4 | Authenticode (önce var/yok) | P1 | Güçlü triyaj | **done** (varlık; doğrulama yok) |
| 5 | Section entropy (ELF) | P1 | Packed sinyali | **done** |
| 6 | TLSH | P2 | Korpus gelince | **done** |
| 7 | FLIRT/BSim | P2 | Context küçültme; heuristic ile başla | **heuristic done**; FID/BSim açık |
| 8 | `CROWBAR_TOOL_PROFILE` | — | Hızlı tarama / derin analiz ayrımı | **done** |

## Ölçüm: unique contribution
Her araç için:
```
unique(tool) = tool açıkken bulunan benzersiz bulgu
             − diğer araçların da ürettiği
```
`CROWBAR_TOOL_PROFILE` ile aç/kapat, aynı örnek setinde karşılaştır. Yalnızca
`unique > 0` olan araçları `core`'a al.

**Durum: açık.** Profil mekanizması hazır (`core` = capa/FLOSS/Ghidra olmadan hızlı tarama; `deep` = hepsi), ama
araç başına benzersiz katkı **ölçülmedi**; bu bir koşu/ölçüm işidir, kod değil.

## Test/DoD
Uygulanan 8 madde için (680 test geçti, 8 POSIX-only atlandı):
- [x] Araç yoksa çökmez, `[]` + log.
- [x] `findings` şemasına uygun kayıt üretir (her bulgu `finding_id` ve `verified` taşır).
- [x] Birim test (mock çıktı ile) eklenir.
- [x] `report.py` ilgili bölümü gösterir (imphash, TLSH, entropy, PE metadata; ham ELF import'u bulgu olmadığı için gösterilmez).
- [x] `pytest` geçer.

Açık (bu belgenin kapsamında): FID/BSim, `osslsigncode`, `elf_library` (NEEDED), TLSH benzerlik karşılaştırması,
unique-contribution ölçümü.

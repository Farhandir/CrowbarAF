# Verifier audit — before/after (qwen8)

**Örnek:** `bin_clean` (gaslighter) · **İddia:** 22 · **Ground truth:** build_target URL kurar,
main yazdırır (bağlanmaz), gerisi CRT/thunk.

## Önce (global kanıt)
| durum | adet | not |
|---|---|---|
| verified_claim | 8 | **4'ü yanlış/misattributed → precision %50** |
| verified_observation | 11 | ~2'si yanlış yorum |
| unverified | 3 | 2'si aslında doğru (false negative) |

Yanlış ✅ örnekleri:
- `main`: "C2'ye bağlanma davranışı sergiler" → **yanlış** (sadece yazdırıyor)
- `_start`: "Crowbar_Test_Connecting yarası ile eşleşir" → **yanlış atıf** (yara `main`'de)
- `0x101020` (12B stub): "'gate.php' URL'sini taramıştır" → **yanlış**
- `build_target`: "URL'yi oluşturur" → **doğru ama ⚠️** (literal koddA yok)

Doğrulayıcı recall: **7 yanlıştan 1'i** yakalandı (~0.14).

## Sonra (fonksiyon-yerel)
| durum | adet |
|---|---|
| verified_claim | **0** |
| file_level | 8 |
| verified_observation | 11 |
| unverified | 3 |

Sonuç: **yanlış ✅ kalmadı**; doğru ama global iddialar `file_level` olarak korundu.

## Not
Bu audit elle etiketlendi (tek örnek). Gelecekte otomatik audit aracı eklenmeli.

# Deney Arşivi

> Bu belge önce **düzeneği** (ne, neden, nasıl ölçülüyor) anlatır; sonra kayıtları
> ve şemayı verir. Deneyleri okumadan önce burayı oku.

---

# 0. Düzenek — neyi, nasıl ölçüyoruz?

## 0.1 Tek soru
**"LLM'e daha az kod verirsek (context'i küçültürsek) kararları bozulur mu?"**

Bunu ölçmek için dört şey gerekir: **örnek** (fonksiyonlar), **doğru cevap**
(ground truth), **strateji** (kodu verme biçimi), **metrik**.

## 0.2 Akış
```
Örnek (fonksiyonlar + ground truth)
   │
   ├── ORACLE: tam kod, sınırsız bütçe ───────────► LLM ──► kararlar (referans)
   │
   └── STRATEJİ: kırp / öncelikle ele / eşik ─────► LLM ──► kararlar
                                                             │
   Metrikler: token (maliyet), coverage, fidelity, GT precision/recall, stability
```

## 0.3 İki farklı görev (karıştırma!)
| Görev | Soru | Örnek |
|---|---|---|
| **Recovery** | "Sırrı/anahtarı çıkar" | L0–L4 merdiveni (JS) |
| **Detection** | "Şüpheli mi, değil mi?" | Fidelity deneyleri |

Obfuscation **recovery**'yi yener (L2'de araç 0/7, LLM 0/3) ama **detection**'da
kararlar kısmen korunabilir. İki sonuç çelişmez; farklı görevler.

## 0.4 Örnekler (dataset)
| Örnek | İçerik | Neden |
|---|---|---|
| **Düz sentetik** (6 fonk) | payload (büyük XOR), decode, checksum, wrapper, noise (büyük decoy), add | En kontrol edilebilir referans |
| **Obf eşleşmiş** (6) | Aynı 6; sabit gizleme `(0x2d+0x2d)`, opaque predicate, fn pointer | Tek değişken obfuscation (adil A/B) |
| **Güçlü obf** (13) | 1 payload (CFF) + 6 aynı-görünümlü decoy + decoder/checksum/wrapper/main/opaque/add | Decoy baskısı + büyük kod |
| **Anonim** (13) | Aynı 13, isimler `FUN_401000` | İsim sızıntısını kaldırmak |
| **Low-priority payload** (13) | Aynı 13, payload priority **0** | Eşik filtresinin kör noktası |

## 0.5 Ground truth
Elle etiketlendi:
- **Şüpheli:** payload, decoder, wrapper (gerçekten zararlı işi yapanlar)
- **Benign:** decoy'lar, checksum, add, main, opaque

## 0.6 Stratejiler (kodu LLM'e verme biçimleri)
| Strateji | Fonksiyon seçimi | Kod bütçesi | Kanıt | Ne test eder |
|---|---|---|---|---|
| `full` (**oracle**) | Hepsi | Sınırsız | Var | Referans (tam context) |
| `truncated` | Hepsi | Küçük | Yok | Sadece kırpma |
| `priority` | Toplam bütçe dolunca düşükleri atla | Küçük | Yok | Sert eleme |
| `priority_ev` | Aynı | Küçük | **Var** | Eleme + kanıt |
| `priority_soft` | **Atlama yok**; düşük önceliğe küçük bütçe | Küçük | Yok | Yumuşak eleme |
| `priority_soft_ev` | Aynı | Küçük | **Var** | Yumuşak + kanıt |
| `priority_threshold` | Öncelik < eşik olanı **tamamen atla** | Küçük | Yok | Eşik filtresi |
| `priority_threshold_ev` | Aynı | Küçük | **Var** | Eşik + kanıt |

- **Bütçe:** fonksiyon başına LLM'e giden metnin token sınırı (kod + kanıt + çocuk özetleri).
  Kod uzunsa **başı/sonu korunarak kırpılır**.
- **Kanıt:** deterministik araç bulguları (capa, FLOSS, IoC, import combo). `_ev`'liler ekler.
- **Öncelik:** gerçek hatta capa +5, tehlikeli API +4, import combo +4, büyük −2, kütüphane 0.

## 0.7 Metrikler
| Metrik | Anlamı | İyi |
|---|---|---|
| **coverage** | analiz edilen / toplam fonksiyon | yüksek |
| **token / tasarruf** | harcanan context; oracle'a göre % | yüksek tasarruf |
| **fidelity** | strateji kararı oracle kararıyla aynı mı | yüksek **ama** oracle yanlışsa yanıltıcı |
| **GT precision** | işaretlenenlerin kaçı gerçekten şüpheli | yüksek |
| **GT recall** | gerçek şüphelilerin kaçı yakalandı | **kritik** |
| **stability** | tekrarda aynı cevap mı | 1.0 = deterministik |

### Bir satır nasıl okunur?
```
priority_threshold   fonk=5  coverage=0.38  GT-P=1.00  GT-R=1.00  token=7129
```
→ 13'ün 5'ini analiz etti; işaretlediklerinin hepsi doğru (P=1.0); tüm gerçek
şüphelileri buldu (R=1.0); 7.129 token (oracle 82.778 → %91 tasarruf).

## 0.8 Tuzaklar
1. **Fidelity yanıltıcı:** oracle yanlışsa, ona uymak doğru değildir → GT şart.
2. **İsim sızıntısı:** `payload`/`decoy_0` cevabı verir → `FUN_...` kullan.
3. **Oracle gürültüsü:** 9B model decoy'lara kanıyor; "referans" kusursuz değil.
4. **Determinizm:** `temperature=0` → aynı cevap; n=5 varyans katmıyor.
5. **Coverage tuzağı:** yüksek tasarruf, fonksiyon atlayarak geliyorsa payload kaçabilir.
6. **Sentetik sınır:** gerçek binary değil; genelleme için gerçek örnek şart.

## 0.9 Tek cümle
**Kırpmak güvenli (recall korunur); atlamak riskli (payload kaçabilir); ve
"oracle'a benzemek" değil, "gerçeği bulmak" ölçülmeli.**

---

# 1. Şema
```jsonc
{
  "experiment_id": "llm_l0_l4_js_qwen8_n3",
  "date": "YYYY-MM-DD",
  "question": "...",
  "dataset":  { "name": "...", "kind": "...", "levels": [...], "ground_truth": "..." },
  "victim":   { "system": "direct_llm | crowbar_llm_layer | crowbar_pipeline | rea | deterministic_only" },
  "model":    { "name": "...", "provider": "ollama|vllm|openai", "params": "9B", "quant": "Q8_0" },
  "config":   { "think": false, "temperature": 0, "num_ctx": 32768, "num_predict": 1400, "runs": 3 },
  "metrics":  { /* koşul bazında oranlar/sayılar */ },
  "results":  [ /* satır bazında ham sayılar */ ],
  "raw_sources": [ "..." ],
  "notes": "dürüst sınırlar"
}
```

# 2. Kayıtlar
Tam liste: `experiments.json` (17 kayıt). Öne çıkanlar:

| experiment_id | Veri | Model | Ana metrik |
|---|---|---|---|
| `llm_l0_l4_js_qwen8_n3` | JS L0–L4 | qwen8 | L2–L4 sır **0/3**; L0/L1 3/3 |
| `evidence_ablation_js_qwen8_n3` | JS L2/L3 | qwen8 | kirli kanıt **0→3/3 yanlış** |
| `deterministic_layer_js` | JS L0–L4 | – | L2/L3 **7/7** sinyal, L4 3/7 |
| `fidelity_synthetic_qwen8_n1` | düz (6) | qwen8 | priority_soft %58, recall 1.0 |
| `fidelity_obf_matched_qwen8_n1` | obf (6) | qwen8 | kanıtla fidelity 1.0, %64 |
| `fidelity_strong_obf_anon_qwen8_n1` | güçlü obf (13, anonim) | qwen8 | threshold **P=1.0, R=1.0, %91** |
| `fidelity_strong_obf_lowprio_qwen8_n1` | payload priority 0 | qwen8 | threshold **R=0.67** (payload kaçtı) |
| `budget_sweep_strong_obf_qwen8_n1` | güçlü obf | qwen8 | tasarruf ~%87'de doyuyor, recall 1.0 |

# 3. Yeni koşu ekleme (ör. API / 27B)
1. Aynı veri kümesi + **aynı `config`** (num_ctx, runs, strateji…).
2. `experiments.json`'a yeni kayıt; `experiment_id`'de modeli belirt.
3. `model` alanını doldur: `provider`, `name`, `params`, `quant`.
4. `raw_sources`'a yeni ham çıktı dosyasını yaz.
5. `metrics`'i aynı anahtarlarla doldur → doğrudan kıyaslanır.

**Kritik kural:** veri kümesi + config sabit; yalnızca `model`/`victim` değişmeli.

# 4. Dürüst notlar
- Çoğu kayıt **sentetik**; gerçek malware değil.
- Fidelity kayıtları **n=1** (model deterministik olduğu için).
- `verifier_before_after` elle etiketlendi.
- Sonuçlar **9B lokal model** için; frontier açık soru.
- **Prompt dili 2026-10-24'te İngilizceye çevrildi.** Bu tarihten önceki kayıtlar
  Türkçe prompt ile üretildi; dil model davranışını değiştirebilir. Bu sınırın iki
  tarafındaki kayıtları doğrudan kıyaslamayın; gerekirse yeniden koşun.
- **Kanıt kanalı sertleştirmesi 2026-10-25.** Bulgu seçimi `findings[:20]` yerine
  sıralı + bütçeli + izlenebilir; bulgular `DATA: {...}` JSON olarak render ediliyor;
  talimat benzeri string'ler karantinaya alınıyor (içerik modele gitmiyor, izde kalıyor);
  sistem prompt'u tool çıktısını da kapsıyor; talimat destekli iddialar `unverified`.
  **P0 (aynı gün):** dört durumlu dosya verdict'i (`malicious/needs_review/unknown/no_evidence`),
  fail-closed backstop ve iki katmanlı kanıt (yerel + global digest). Bu tarihten önceki ve
  sonraki kayıtlar doğrudan kıyaslanmamalı; gerekirse yeniden koşun.

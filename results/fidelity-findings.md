# Faz 1 — Fidelity deneyi

**Model:** qwen8 (Qwen3.5-9B Q8_0) · **Örnek:** 6 fonksiyon (2 büyük, 4 küçük; 2 benign)
**Oracle:** tam context · **Ölçüm:** karar uyumu (fidelity), recall, token

## Sonuçlar (v2 — priority_soft dahil)
| strateji | analiz | fidelity | recall | kaçan | token | tasarruf |
|---|---|---|---|---|---|---|
| **full (oracle)** | 6 | 1.00 | 1.00 | – | 21.475 | – |
| **truncated** | 6 | 1.00 | 1.00 | – | 12.234 | %43 |
| **priority** (sert eleme) | 5 | 1.00 | **0.75** | `0x402000` | 7.499 | %65 |
| **priority_soft** | **6** | **1.00** | **1.00** | – | **8.975** | **%58** |
| **priority_soft_ev** | **6** | **1.00** | **1.00** | – | 9.038 | %58 |

## Bulgular
1. **Kırpma bedava kazanç:** kod kırpma kararları değiştirmedi, **%43** tasarruf.
2. **Sert eleme riskli:** %65 tasarruf ama **recall 0.75** — düşük öncelikli şüpheli
   fonksiyon (`noise`) tamamen kaçtı.
3. **Yumuşak bütçe en iyi denge:** `priority_soft` **%58 tasarruf + recall 1.00**.
   Düşük öncelikliye 400 token ayırmak, onu atmadan kararı kurtardı.
4. **Kanıt maliyeti ihmal edilebilir:** +63 token; bu örnekte kararı değiştirmedi.

## Çıkarım
> Düşük öncelikli fonksiyonu **atlamak yerine küçük bütçeyle özetle**.
> Böylece context'i yarıya indirirken yanlış negatifi önlersin.

Bu, "decision-preserving context compression" tezinin ölçülmüş ilk kanıtı:
**~%58 daha az token, aynı kararlar, kaçan şüpheli yok.**

## Dürüst sınırlar
- Tek örnek (6 fonksiyon), **sentetik**, n=1 → gösterge, kesin sonuç değil.
- Gerçek malware dağılımı ve öncelik skoru farklı olacak.
- Fidelity oracle'ı da yanılabilir (oracle = aynı model, tam context).

## Sıradaki
1. n≥5 + daha büyük/gerçek örnek (S2–S4).
2. Öncelik skorunun recall'unu ölç (gerçek payload priority 0 ise?).
3. Bu stratejiyi CrowbarAF hattına varsayılan yap (`low_priority_budget`).

---

# Strong obfuscated (13 fonksiyon, CFF + 6 decoy) — qwen8

**GT şüpheli:** payload, decoder, wrapper (3). Diğerleri benign.

| strateji | analiz | fidelity | GT-P | GT-R | token | tasarruf |
|---|---|---|---|---|---|---|
| oracle | 13 | 1.00 | **0.30** | 1.00 | 82.909 | – |
| truncated | 13 | 0.92 | 0.27 | 1.00 | 32.519 | %61 |
| priority_soft | 13 | 0.92 | 0.27 | 1.00 | 16.746 | %80 |
| **priority_threshold** (min_priority=1) | **5** | **1.00** | **0.75** | **1.00** | **7.411** | **%91** |

## Bulgular
1. **Fidelity yanıltıcı:** oracle'a uyum yüksek olsa da GT precision 0.27–0.30.
   Model 6 decoy'un 5'ini yanlış pozitif işaretledi.
2. **Deterministik eşik (min_priority=1) precision'ı 0.30 → 0.75 yaptı**,
   recall 1.00 kaldı, **%91 tasarruf**.
3. **Ama coverage 0.38** (13'te 5). Priority 0 bir payload olsaydı **kaçardı**.
4. Kalan tek FP: `main` (payload'ı çağırdığı için).

## Dürüst sınır
- Bu sonuç **9B lokal model** için. Frontier/büyük modelde precision artabilir;
  "LLM karar mercii olamaz" değil, **"9B'de olamaz; frontier açık soru."**
- Sentetik + n=1. Öncelik skorunun recall'u üretimde kritik.

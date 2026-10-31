# HANDOFF — Remaining Study Work (Items 1–5)

> Bu belge, “VM smoke”tan gerçek malware setine kadar kalan **tüm** işi tek
> paket olarak tanımlar. Amaç bir arkadaşa geniş bir iş vermek; ancak gerçek
> malware custody’si, API anahtarları ve nihai etik/legal onay **sende kalır**.

## 0. Sahiplik matrisi

| İş | Arkadaş yapabilir | Sende kalır |
|---|---|---|
| 1. VM smoke | ✅ kurulum, state, validation, rapor | VM erişimi/son onay |
| 2. Baseline freeze | ✅ harness + benign/synthetic koşular | API bütçesi/anahtarı, nihai kabul |
| 3. Real-sample protocol | ✅ doküman/protokol taslağı | örnek temini, custody, etik/legal onay |
| 4. Frontier + REA adapters | ✅ adapter iskeleti, fake testler | gerçek API key/hesap/ToS onayı |
| 5. Metrics/reporting | ✅ metrik aracı, CI, tablolar | nihai yorum/rapor onayı |
| Gerçek malware batch | ❌ (izin verilmeden) | ✅ örnek, VM, etiket, yayın |

**Altın kural:** Arkadaş gerçek malware indirmez/çalıştırmaz; API anahtarı
istemez/paylaşmaz. Gerçek örnek gerekiyorsa durur ve sana haber verir.

## 1. VM smoke (ilk kapı)

Ayrıntı: [`HANDOFF-VM-SMOKE.md`](HANDOFF-VM-SMOKE.md).

- Offline VM, 3 benign örnek (`/bin/true`, `/bin/ls`, C hello-world).
- `--no-llm --no-db` → `state.json`; fonksiyon/finding/izin kontrolü.
- `sandbox/validate_state.py` + testleri.
- Host `host_analyze.py` (lokal model varsa).
- `sandbox/smoke_report.md` + PR.

**Kabul:** 3/3 state, ≥1 fonksiyon, key yok, state `600`, testler geçiyor.

## 2. Baseline freeze (C + global digest)

Amaç: arşivdeki A/C karışıklığını bitirmek.

- Mevcut S1/S3/S4 state’leri ve sample’ları kullan.
- **Aynı decompile kümesi + aynı finding seti** kuralını koru.
- `CROWBAR_TWO_SIGNAL_MALICIOUS=1` (varsayılan) ve global digest ile koş.
- Kritik hücrelerde **n=3**; en az:
  - S1: 100 / 1000 fonksiyon, threshold + naive.
  - S3: benign + injected, threshold + soft + naive.
  - S4: encoded pipeline state, threshold + naive.
- Çıktı: `results/baseline_<tarih>.json` + tablo.
- API/local model: arkadaş kendi lokal modelini kullanabilir; anahtar
  paylaşılmaz. API gerekiyorsa koşuyu sen yaparsın.

**Kabul:** aynı input, n=3, verdict/token/süre/coverage tabloları; sapmalar
raporlanır. Politika değiştirilmez.

## 3. Real-sample protocol (doküman, örnek yok)

Arkadaş **taslak** hazırlar; gerçek örnek indirmez.

- Kaynak ve lisans: MalwareBazaar/VirusShare/benign corpus seçenekleri.
- Hash manifest, aile etiketi, benzersizlik/dedup.
- **Family split**: aynı aile train/test’e karışmaz.
- Gerçek malware’de dosya-seviyesi label; fonksiyon-seviyesi payload testleri
  sentetik kalır.
- Benign set: sistem binary’leri + yaygın araçlar; lisans/dağıtım notu.
- Depolama: şifreli kasa, `600`, git dışı, erişim kaydı.
- Etik/legal: çalıştırma yok, dağıtım yok, sadece statik; sorumlu kişi.
- Örnek boyutu/hedef sayı ve istatistiksel güç.

**Kabul:** `docs/REAL-SAMPLE-PROTOCOL.md` taslağı; senin onayın olmadan örnek
temini yok.

## 4. Frontier + REA adapters (iskelet)

- GPT/Claude/OpenCode Go için provider adapter iskeleti; model sürümü pinleme.
- Refusal, rate limit, context limit, cost/usage kaydı.
- REA prior-art baseline wrapper’ı; aynı decompile/finding seti.
- Testler **fake client** ile; gerçek çağrı yok.
- Anahtarlar sadece env; repo/VM’e yazılmaz.

**Kabul:** adapter testleri, aynı input sözleşmesi, maliyet/refusal alanları;
gerçek API çağrısı senin onayınla.

## 5. Metrics + reporting

- Dosya verdict dağılımı: `malicious / needs_review / unknown / no_evidence`.
- Payload recall, benign FP, review load, coverage, token, süre.
- `unknown` oranı ve **nedeni**.
- n=3 ortalama + güven aralığı.
- “FP/FN yok” deme; hangi koşulda `unknown`/`needs_review` olduğunu yaz.
- Çıktı: `results/` JSON + Markdown tablo; CI’da test.

**Kabul:** metrik aracı + testleri; aynı JSON’dan yeniden üretilebilir tablo.

## 6. Gerçek malware batch (senin liderliğinde)

Sadece 1–2–3–4 kapıları geçtikten sonra:

- Örnek custody ve VM senin kontrolünde.
- İlk tur lokal 9B; bulut API ayrı onay/ToS.
- 3–5 örnek smoke → 20–50 örnek pilot → hedef set.
- Arkadaş destek veriyorsa sadece offline VM’de, anahtarsız.

## 7. Git / PR akışı

```bash
git checkout -b handoff/full-study
git push -u origin handoff/full-study
```

- Alt görevler ayrı PR olabilir:
  - `handoff/vm-smoke`
  - `handoff/baseline`
  - `handoff/protocol`
  - `handoff/adapters`
  - `handoff/metrics`
- `main`’e direkt push yok; branch protection + review.
- PR’larda state/sample/`.env` yok.
- Her PR’da: ne yapıldı, nasıl test edildi, eksikler.

## 8. Önerilen sıra

1. **VM smoke** (kapı).
2. **Protocol taslağı** (paralel, örnek yok).
3. **Baseline freeze** (benign/synthetic; lokal model).
4. **Metrics + adapters** (kod, fake testler).
5. **Senin onayın** → gerçek örnek batch.

## 9. Arkadaşa kısa mesaj

> CrowbarAF’de kalan çalışmanın bir kısmını devretmek istiyorum.
> `docs/HANDOFF-FULL-STUDY.md` ve `docs/HANDOFF-VM-SMOKE.md` ile başla.
> Gerçek malware/API key yok; benign/synthetic ve lokal model. VM smoke’u
> geçtikten sonra baseline/metrics/adapters PR’ları açabilirsin.
> Gerçek örnek veya bulut API gerekirse önce bana sor.

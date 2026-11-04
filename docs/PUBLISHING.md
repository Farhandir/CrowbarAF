# Public Repo Checklist

> Soru: “Repoyu public yaparsak çalınma/risk durumu ne olur?”
>
> Kısa cevap: **Public repo teknik olarak klonlanabilir/forklanabilir; bunu
> engelleyemezsin.** Lisans sadece hukuki kullanım şartlarını belirler. Asıl
> riskler secret, gerçek malware/state, kişisel veri ve yayınlanmamış sonuçlardır.

## 1. Mevcut tarama (2026-11-04)

| Kontrol | Sonuç |
|---|---|
| `.env` tracked | ❌ yok; sadece `.env.example` |
| `.env` git geçmişi | ❌ yok |
| Gerçek API key | ❌ bulunmadı; sadece test fixture’larında `sk-short` gibi sahte değerler |
| Gerçek malware binary | ❌ yok |
| State/DB tracked | sadece `results/archive/raw/state_scale_enc_fixed2.json` (sentetik encoded örnek; 192.0.2.1 dokümantasyon IP’si) |
| Kişisel yol | ✅ çalışma ağacı + git geçmişi temizlendi (history rewrite) |
| Commit e-postaları | ✅ GitHub noreply adreslerine çevrildi (history rewrite) |
| Secret taraması | ✅ gitleaks 0 (imphash allowlist), trufflehog 0 |
| LICENSE / SECURITY / CITATION | ✅ Apache-2.0 + NOTICE + SECURITY.md + CITATION.cff |
| `.github` CI / CODEOWNERS | ❌ yok |
| Repo boyutu | ~9 MiB; büyük binary yok |
| Branch | `master`; arkadaş doğrudan push etmiş, PR/branch protection yok |

## 2. Public olunca ne olur?

### Çalınma / kopyalama
- Public repo **herkes tarafından klonlanır/forklanır**; bunu teknik olarak
  engelleyemezsin.
- **Lisans** ne yapılabileceğini belirler:
  - `MIT` / `Apache-2.0`: ticari kullanım dahil geniş kullanım.
  - `GPL-3.0`: türevler de GPL olmak zorunda.
  - `All rights reserved`: görüntülenebilir ama yeniden kullanılamaz; yine de
    kopyalanmasını teknik olarak durdurmaz.
- “Çalınma” endişesi varsa **private + collaborator** daha uygun. Public,
  işbirliği/atıf/görünürlük için tercih edilir.

### Gerçek riskler
1. **Secret sızıntısı**: API key, token, `.env`, CI secret.
2. **Gerçek malware / state**: public repoda malware barındırma GitHub ToS ve
   güvenlik riski; state’ler C2 string’leri içerebilir.
3. **Kişisel veri**: commit e-postaları, `/home/...` yolları, kullanıcı adları.
4. **Yayınlanmamış araştırma**: sonuçların/veri setinin erken görünmesi.
5. **Kötü niyetli issue/PR**: branch protection ve review gerekir.
6. **Scraping / model eğitimi**: public kodun toplanması engellenemez.

## 3. Public yapmadan önce yapılacaklar

- [x] `gitleaks` / `trufflehog` ile **tüm git geçmişi** tarandı: 0 gerçek secret.
- [ ] Daha önce paylaşılmış herhangi bir gerçek key varsa **rotate et**.
- [x] Yerel ev dizini yolları çalışma ağacından ve git geçmişinden temizlendi.
- [x] Kişisel commit e-postaları GitHub noreply ile değiştirildi (history rewrite).
- [ ] `git ls-files` ile gerçek örnek/DB/state olmadığını doğrula.
- [x] Lisans: **Apache-2.0**; `LICENSE` + `NOTICE` eklendi.
- [x] `SECURITY.md` + `CITATION.cff` eklendi (yazar listesi makale için güncellenecek).
- [ ] Branch protection: `master`’a doğrudan push yok; PR + test zorunlu.
- [ ] CI: `pytest -q`, `python scripts/check_tools.py` (secret yok).
- [ ] Gerçek malware/state için `.gitignore` + şifreli kasa kuralı.
- [ ] Public yapmadan önce son kez `git status` / `git log --stat` kontrolü.

## 4. Lisans seçenekleri

| Lisans | Ne yapar? | Ne yapmaz? | Kim için? |
|---|---|---|---|
| **MIT** | Kullanım, değiştirme, dağıtma, ticari kullanım serbest; copyright + lisans metni korunur | Patent garantisi yok; türevler kapalı kaynak olabilir | En basit, geniş kullanım |
| **Apache-2.0** | MIT benzeri + açık patent lisansı + NOTICE yükümlülüğü | Türevler kapalı olabilir; marka hakkı vermez | Kurumsal/akademik işbirliği |
| **GPL-3.0** | Türev dağıtılırsa kaynak da GPL olmalı | Kapalı kaynak türev dağıtımı yok | Açık kalmasını istiyorsan |
| **AGPL-3.0** | GPL + ağ üzerinden kullanımda da kaynak açma | Kapalı SaaS yok | Sunucu/SaaS için |
| **MPL-2.0** | Dosya bazında copyleft | Tüm proje GPL olmak zorunda değil | Orta yol |
| **Unlicense/CC0** | Kamu malı; atıf şartı yok | Patent/atıf koruması zayıf | Atıf istemiyorsan |
| **Özel / All rights reserved** | Görüntülenebilir, yeniden kullanım yok | Açık kaynak değil; yine de kopyalanabilir | Sadece görünürlük |

**Seçilen:** **Apache-2.0** (kod için). Makale metni/figürleri ve veri seti
ayrı lisanslarla paylaşılmalı; üçüncü taraf araçlar ve malware örnekleri bu
lisansa dahil değildir.

**Kısa öneri:**
- Geniş kullanım + atıf + patent koruması: **Apache-2.0**.
- En basit: **MIT**.
- Türevler açık kalsın: **GPL-3.0**.
- “Kimse kapalı üründe kullanmasın” diyorsan: **GPL-3.0** (veya ticari kullanımı sınırlayan özel lisans; ama bu açık kaynak olmaz).

Lisans **kopyalamayı teknik olarak engellemez**; sadece hukuki kullanım şartını belirler. Public repo herkes tarafından fork’lanabilir.

## 5. Public yapma kararı

**Öneri:** Gerçek malware çalışması ve yayın olgunlaşana kadar **private**
tut; arkadaşı collaborator olarak ekle. Public’e geçilecekse yukarıdaki checklist
tamamlanmalı; aksi halde secret/kişisel veri/erken sonuç riski var.

## 6. Kurulum (public/private fark etmez)

```bash
./scripts/setup.sh --with-tools
source .venv/bin/activate
python scripts/check_tools.py
```

- Python paketleri: `requirements.txt` + `requirements-tools.txt`.
- Ghidra/JDK/readelf/UPX **pip ile kurulmaz**; `docs/SETUP.md`.
- `py-tlsh` opsiyonel; C derleyicisi yoksa atlanabilir.

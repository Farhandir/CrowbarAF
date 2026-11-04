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
| Kişisel yol | ✅ çalışma ağacında temizlendi (geçmiş için history rewrite gerekir) |
| Commit e-postaları | ⚠️ iki kişisel e-posta public olur |
| LICENSE / SECURITY / CITATION | ❌ yok |
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

- [ ] `gitleaks` / `trufflehog` ile **tüm git geçmişini** tara.
- [ ] Daha önce paylaşılmış herhangi bir gerçek key varsa **rotate et**.
- [x] Yerel ev dizini yolları temizlendi; geçmiş için history rewrite yapılmalı.
- [ ] Kişisel commit e-postalarını GitHub noreply ile değiştir (history rewrite).
- [ ] `git ls-files` ile gerçek örnek/DB/state olmadığını doğrula.
- [ ] Lisans kararı ver ve `LICENSE` ekle (MIT / Apache-2.0 / GPL-3.0 / özel).
- [ ] `SECURITY.md` (iletişim + kapsam) ve `CITATION.cff` ekle.
- [ ] Branch protection: `master`’a doğrudan push yok; PR + test zorunlu.
- [ ] CI: `pytest -q`, `python scripts/check_tools.py` (secret yok).
- [ ] Gerçek malware/state için `.gitignore` + şifreli kasa kuralı.
- [ ] Public yapmadan önce son kez `git status` / `git log --stat` kontrolü.

## 4. Public yapma kararı

**Öneri:** Gerçek malware çalışması ve yayın olgunlaşana kadar **private**
tut; arkadaşı collaborator olarak ekle. Public’e geçilecekse yukarıdaki checklist
tamamlanmalı; aksi halde secret/kişisel veri/erken sonuç riski var.

## 5. Kurulum (public/private fark etmez)

```bash
./scripts/setup.sh --with-tools
source .venv/bin/activate
python scripts/check_tools.py
```

- Python paketleri: `requirements.txt` + `requirements-tools.txt`.
- Ghidra/JDK/readelf/UPX **pip ile kurulmaz**; `docs/SETUP.md`.
- `py-tlsh` opsiyonel; C derleyicisi yoksa atlanabilir.

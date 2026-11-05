# UI v2 — Offline VM + Host LLM

v2 arayüzü aynı FastAPI uygulamasında, `/v2` yolunda çalışır. Eski tam hat UI
`/` yolunda korunur.

```bash
python main.py --serve --host 127.0.0.1 --port 8000
# tarayıcı: http://127.0.0.1:8000/v2
```

## Sekmeler

### 1. Offline (VM)

- Dosya seç / sürükle-bırak.
- VM adı, kullanıcı, şifre, repo yolu, profil, timeout ayarları.
- **İncele (VM)** → host, `VBoxManage guestcontrol` ile örneği VM'e kopyalar,
  `main.py --no-llm --no-db` çalıştırır ve `state.json`'u geri alır.
- Çıktı: state indirme bağlantısı.
- VM'de ağ/clipboard/shared folder/USB gerekmez.
- VM açık ve Guest Additions kurulu olmalı.
- Şifre yalnızca istek/job süresince bellekte tutulur; state'e/DB'ye yazılmaz.

Gereksinimler:

- VirtualBox + `VBoxManage` host PATH'inde.
- VM'de `kali` kullanıcısı ve repo:
  `/home/kali/Desktop/CrowbarAF`
- VM'de `.venv`, Ghidra, capa, FLOSS, YARA, UPX.
- Host ve Guest Additions sürümlerini mümkünse eşitleyin.

### 2. Host / LLM

- Offline'dan gelen `state.json`'u yükle.
- Provider/model/base URL, token bütçesi, worker ve priority ayarları.
- **LLM ile işle** → state doğrulanır, LLM + policy C çalışır, verdict/rapor/DB
  üretilir.
- API key yalnızca host ortamında (`CROWBAR_LLM_API_KEY`); UI'den istenmez.
- Gerçek malware için lokal model kullanın.

### 3. History / Compare

- SQLite'taki analizler.
- Satıra tıklayınca verdict, rapor ve bulgular.
- Offline state ile LLM sonucunu aynı örnek hash'i üzerinden karşılaştırabilirsiniz.

### 4. Setup

- Host araç kontrolü: `scripts/check_tools.py`.
- v2'nin bu ilk sürümünde **durum kontrolü** var; otomatik Ghidra/JDK/UPX
  kurulum butonları sonraki adım.
- VM içi araçları VM'de doğrulayın:
  ```bash
  cd ~/Desktop/CrowbarAF
  source .venv/bin/activate
  python scripts/check_tools.py
  ```

## Güvenlik

- v2 UI yalnızca `127.0.0.1` için tasarlandı; internete açmayın.
- `state.json` düşman verisidir: boyut/şema/izin doğrulaması yapılır, çalıştırılmaz.
- VM compromise şüphesinde **transfer etmeyin**; snapshot'a dönüp yeniden analiz edin.
- `state.json` C2 string'leri içerebilir; `600`, git dışı, lokal model.
- GuestControl şifresini repoya/DB'ye koymayın.

# UI v2 — Offline VM + Host LLM

v2 arayüzü aynı FastAPI uygulamasında, `/v2` yolunda çalışır. Eski tam hat UI
`/` yolunda korunur.

```bash
python main.py --serve --host 127.0.0.1 --port 8000
# tarayıcı: http://127.0.0.1:8000/v2
```

## Sekmeler

### 1. Offline (VM)

- **İki kaynak modu:**
  - **Host'tan dosya yükle:** benign/sentetik testler.
  - **VM içindeki dosya yolu:** gerçek malware için önerilen. Örnek host'a
    kopyalanmaz; VM'deki mutlak yol (`/home/kali/samples/sample.bin`) doğrudan
    analiz edilir ve yalnızca `state.json` host'a döner.
- VM adı, kullanıcı, şifre, repo yolu, Ghidra/capa/YARA yolları, profil, timeout ayarları.
- **Decompile modu:**
  - `auto` (önerilen): ≤300 fonksiyon → hepsi; daha büyükse ilk 300.
  - `all`: tüm fonksiyonlar.
  - `top`: yalnızca `Max decompile` kadar.
- Coverage artık **tüm fonksiyonlar** üzerinden raporlanır; 100/170 = %59,
  "98/98 = %100" değil.
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
- **OpenCode Go** hazır seçeneği: base URL
  `https://opencode.ai/inference/go/openai` (istemci `/v1/chat/completions`
  ekler), model `deepseek-v4.1-flash`. API key yalnızca host ortamında
  `CROWBAR_LLM_API_KEY` olarak durur; UI key istemez.
- **LLM ile işle** → state doğrulanır, LLM + policy C çalışır, verdict/rapor/DB
  üretilir.
- API key yalnızca host ortamında (`CROWBAR_LLM_API_KEY`); UI'den istenmez.
- Policy C v2: LLM-only durumda en az 3 şüpheli fonksiyon, en az 2 farklı
  davranış sınıfı ve %60 coverage varsa `malicious`; aksi halde
  `needs_review`. Deterministic sinyaller varsa mevcut iki-sinyal kuralı geçerli.
- Gerçek malware için lokal model kullanın.

### 3. History / Compare

- SQLite'taki analizler.
- Satıra tıklayınca verdict, rapor ve bulgular.
- Detaydan **HTML rapor indir**, **Markdown rapor indir** ve **JSON indir**.
- Rapor `report.py` ile üretilir; HTML sürümü tablo/rozet düzeninde, script içermez,
  IoC'ler defang edilir.
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
- **Gerçek malware'i host'a indirmeyin.** VM içinde indirin veya ayrı bir
  download VM'inden aktarın; UI'de **VM içindeki dosya yolu** modunu kullanın.
- VM compromise şüphesinde **transfer etmeyin**; snapshot'a dönüp yeniden analiz edin.
- `state.json` C2 string'leri içerebilir; `600`, git dışı, lokal model.
- GuestControl şifresini repoya/DB'ye koymayın.

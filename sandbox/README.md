# Split VM / Host Mode

> Amaç: gerçek malware’e **dokunan** deterministik araçları, **API key/card
> bulunmayan offline** bir VM’de çalıştırmak; LLM çağrılarını host’ta yapmak.

```text
┌────────────────────────────────────┐
│ Offline analiz VM                  │
│                                    │
│ Ghidra / capa / FLOSS / YARA /     │
│ UPX / pefile                       │
│                                    │
│ main.py --no-llm --no-db           │
│ key YOK, kart YOK, ağ YOK          │
│ malware ÇALIŞMAZ                   │
└──────────────┬─────────────────────┘
               │ sadece state.json
               ▼
┌────────────────────────────────────┐
│ Host / LLM tarafı                  │
│                                    │
│ host_analyze.py                    │
│ llm_layer + policy C + verdict     │
│ API key SADECE burada              │
└────────────────────────────────────┘
```

## 1. Offline VM

- Ağ kapalı; mümkünse snapshot temiz.
- `.env`, API key, SSH key, tarayıcı hesabı, kart bilgisi **yok**.
- Paylaşılan pano/klasör kapalı; sadece örnek ve çıktı için ayrı dizin.
- Örneği **çalıştırma**; sadece statik araçlara oku.
- Örnek kasası ayrı ve şifreli; `chmod 600`.

VM içinde:

```bash
./sandbox/run_offline_analysis.sh /samples/sample.bin /out/state.json
```

Script şunları yapar:

```bash
export CROWBAR_SKIP_LLM=1
export CROWBAR_SKIP_DB=1
python main.py sample.bin --no-llm --no-db --out state.json
```

`state.json` içinde decompile edilmiş fonksiyonlar ve deterministik bulgular
vardır; **örnek binary yoktur**. Yine de C2 string’leri içerebilir: repoya
commit etme, şifreli/geçici dizinde tut.

## 2. State aktarımı

- VM’den host’a **tek yönlü** kopyala: paylaşılan klasör, `scp`, USB.
- Host’tan VM’e dosya/anahtar gönderme.
- Aktarım sonrası `state.json` iznini `600` yap.
- Host tarafında şema doğrulanır (`AgentState.model_validate_json`), boyut
  sınırı uygulanır, içerik çalıştırılmaz.

## 3. Host / LLM

Yerel model (gerçek malware için önerilen; key yok):

```bash
CROWBAR_LLM_PROVIDER=ollama \
CROWBAR_LLM_MODEL=qwen2.5-coder:7b \
./sandbox/run_host_analysis.sh /out/state.json /out/state.llm.json
```

OpenAI-compatible provider (sadece onaylı/sentetik örneklerde; key host
ortamında, asla VM’de):

```bash
export CROWBAR_LLM_PROVIDER=openai
export CROWBAR_LLM_BASE_URL=https://opencode.ai/inference/go/openai/v1
export CROWBAR_LLM_MODEL=deepseek-v4.1-flash
export CROWBAR_LLM_API_KEY=...          # shell geçmişine yazma
./sandbox/run_host_analysis.sh /out/state.json /out/state.llm.json
```

Host script’i API key’i **CLI argümanı olarak kabul etmez**; sadece ortam
değişkeninden okur. `--out` dosyası `600` izinle atomik yazılır.

## 4. Neden bu ayrım?

| Risk | VM’de anahtar varsa | Ayrık modda |
|---|---|---|
| Parser exploit → VM ele geçer | key çalınabilir | VM’de key yok |
| Malware ağa çıkar | API/card erişimi | VM offline |
| Kart bilgisi | VM’de olabilir | sadece provider/host |
| LLM maliyeti | VM’den kontrolsüz | host’ta limitlenebilir |
| Gerçek malware kodu buluta gider | riskli | lokal 9B / onaylı politika |

## 5. Sınırlar

- Bu mod **statik** analizdir; malware çalıştırılmaz.
- Container/VM parser riskini azaltır, sıfırlamaz. Gerçek malware setinde
  offline yerel VM kullan.
- `state.json` gerçek malware string’leri içerebilir; git’e, buluta, e-posta’ya
  koyma.
- Bulut LLM’e gerçek malware decompile kodu göndermek ToS/gizlilik riskidir;
  ilk turda lokal model kullan.

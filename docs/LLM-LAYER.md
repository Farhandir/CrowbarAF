# LLM Katmanı (`llm_layer/`)

CrowbarAF'ın **LLM tarafı**: pipeline'dan gelen bulguları, sabit bir context
bütçesine **kararı değiştiren bilgiyi koruyarak** sığdırır; bottom-up özetler;
her iddiayı koda/bulgulara bağlar.

## Modüller
| Dosya | Görev |
|---|---|
| `types.py` | `Finding`, `FunctionInfo`, `Claim`, `FunctionSummary` |
| `tokens.py` | token tahmini + baş/son korumalı kırpma |
| `client.py` | model-agnostik istemci (Ollama / OpenAI-uyumlu / vLLM) |
| `context.py` | bütçe-farkında bağlam kurma, öncelikle fonksiyon seçimi |
| `verify.py` | kanıt doğrulayıcı (3 sınıf) |
| `traverse.py` | call graph → SCC → **callee-önce** sıra |
| `summarize.py` | tek fonksiyon prompt'u + katı JSON |
| `pipeline.py` | bottom-up orkestrasyon + token muhasebesi |
| `nodes.py` | `nodes.py`'deki `ai_*` düğümlerinin karşılıkları |
| `factory.py` | ortam değişkenlerinden istemci |

## İz (trace) — ne incelendi?
Her koşu bir **JSON iz** üretir: hangi fonksiyon seçildi/atlandı (ve neden),
kaç context token'ı, hangi kanıtlar, hangi iddialar doğrulandı.

```bash
# iz dizini (varsayılan ./runs)
CROWBAR_LLM_TRACE_DIR=runs

# üretilen izi okunur rapora çevir
python experiments/trace_report.py runs/llm_trace_XXXX.json
```

İzde: `run` (model/butce), `totals` (kapsama, token, doğrulanan/doğrulanamayan),
`functions[]` (durum, skip_reason, context_tokens, code_truncated, claims) ve
`events[]` (zaman çizgisi).

## Kanıt sınıfları
- `verified_claim` — iddia deterministik bir bulguyla örtüşüyor
- `verified_observation` — kanıt koddan birebir alıntı
- `unverified` — hiçbiri → **sarı uyarı** (uydurma olabilir)

## Yapılandırma (model = config)
```bash
# Lokal
CROWBAR_LLM_PROVIDER=ollama CROWBAR_LLM_MODEL=qwen8:latest

# Kiralık GPU / vLLM
CROWBAR_LLM_PROVIDER=vllm CROWBAR_LLM_BASE_URL=http://HOST:8000 CROWBAR_LLM_MODEL=<model>

# API
CROWBAR_LLM_PROVIDER=openai CROWBAR_LLM_BASE_URL=https://api... \
CROWBAR_LLM_API_KEY=... CROWBAR_LLM_MODEL=...
```
Diğer: `CROWBAR_LLM_NUM_CTX` (varsayılan 32768), `CROWBAR_LLM_NUM_PREDICT` (1200).
Eski değişkenler de okunur: `CROWBAR_OLLAMA_MODEL`, `OLLAMA_BASE_URL`.

## Kullanım
```python
from llm_layer import FunctionInfo, Finding, analyze
from llm_layer.factory import from_env

res = analyze(functions, findings, from_env(), budget_tokens=6000)
for off, s in res.summaries.items():
    print(s.summary, s.confidence, [(c.status, c.text) for c in s.claims])
print("token:", res.token_total())
```

Demo (dış veri gerekmez):
```bash
python experiments/llm_layer_demo.py
```

## Test
```bash
python -m pytest -q   # 67 test
```

## Bilinen sınırlar
- `DecompiledFunction` henüz `callees`/`xrefs` taşımıyor; pipeline ekleyince
  bottom-up gezinme tam anlamlı olur (şu an `getattr` ile uyumlu).
- `run_supervisor` şimdilik **deterministik şablon**; LLM sentezi sonra.
- Token tahmini karakter/4; gerçek değer Ollama/OpenAI `prompt_tokens` ile kalibre edilmeli.
- `is_library` alanı `DecompiledFunction`'a eklenince eleme devreye girer.

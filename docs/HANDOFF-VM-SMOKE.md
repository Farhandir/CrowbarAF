# HANDOFF — Split-Mode VM Smoke Test

> Bu görev, CrowbarAF’nin **offline VM → state.json → host LLM** ayrımını
> gerçek malware olmadan doğrulamak için tasarlandı. Görevi bir arkadaşa
> olduğu gibi paslayabilirsin.

## Görev

3 zararsız/benign örnek üzerinde:

1. Offline VM’de `--no-llm --no-db` ile deterministik `state.json` üret.
2. State’in şema, izin ve key sızıntısı kontrollerini yapan
   `sandbox/validate_state.py` aracını yaz.
3. State’i host’a tek yönlü aktar.
4. Host’ta `host_analyze.py` ile (lokal model varsa) verdict/rapor üret.
5. Sonuçları `sandbox/smoke_report.md` olarak raporla ve PR aç.

Bu görev **kod + ortam kurulumu + hata ayıklama** içerir; sadece komut
çalıştırmak değildir. Ghidra PATH’i, araç sürümleri ve state transferi
arkadaşın çözmesi gereken kısımlar.

## Kapsam dışı

- Gerçek malware kullanmak/indirmek/çalıştırmak.
- API key, bulut LLM, ödeme bilgisi kullanmak.
- `verdict`, `compute_verdict`, politika C veya LLM prompt’larını değiştirmek.
- `main` branch’ine doğrudan push etmek.
- State veya örnek dosyaları repoya commit etmek.

## Önkoşullar

- KVM/VirtualBox/VMware ile **offline** bir VM (ağ kapalı, temiz snapshot).
- Repo’nun fork’u veya `handoff/vm-smoke` branch’i.
- VM’de Python venv + repo bağımlılıkları.
- Ghidra (analyzeHeadless PATH’te), capa, FLOSS, YARA, UPX, pefile.
- Host’ta lokal model (Ollama/vLLM) **opsiyonel**; yoksa raporla ve LLM
  aşamasını “çalıştırılmadı” olarak işaretle. Bulut API kullanma.

## Güvenlik kuralları

- VM’de `.env`, `CROWBAR_LLM_API_KEY`, SSH key, tarayıcı hesabı olmasın.
- VM ağ bağlantısı kapalı olsun; paylaşılan pano/klasör kapalı.
- Sadece benign örnekler: `/bin/true`, `/bin/ls`, küçük bir C hello-world.
- State `600` izinli olsun; state/sample commit edilmesin.
- Host’a sadece `state.json` gitsin; host’tan VM’e dosya/anahtar dönmesin.
- Raporda C2/IP gibi string’leri gerekiyorsa redakte et.

## Adımlar

### 1. Branch

```bash
git checkout -b handoff/vm-smoke
git push -u origin handoff/vm-smoke
```

Fork kullanıyorsan PR’ı `main` yerine `handoff/vm-smoke` hedefle.

### 2. Örnekler

```bash
cp /bin/true  /samples/true
cp /bin/ls    /samples/ls
cat > /samples/hello.c <<'EOF'
#include <stdio.h>
int main(void) { puts("hello"); return 0; }
EOF
gcc -O0 -o /samples/hello /samples/hello.c
sha256sum /samples/true /samples/ls /samples/hello | tee /samples/SHA256SUMS
```

### 3. VM’de deterministik state

```bash
./sandbox/run_offline_analysis.sh /samples/true  /out/true.state.json
./sandbox/run_offline_analysis.sh /samples/ls    /out/ls.state.json
./sandbox/run_offline_analysis.sh /samples/hello /out/hello.state.json
```

Kontrol:

- `source_code` en az bir fonksiyon içeriyor mu?
- `llm_summary` alanları boş mu?
- State `600` mü?
- Dosyada `CROWBAR_LLM_API_KEY` veya key benzeri bir değer var mı?

### 4. `sandbox/validate_state.py`

Beklenen davranış:

```bash
python sandbox/validate_state.py /out/true.state.json
# exit 0 + kısa özet
python sandbox/validate_state.py /out/bozuk.json
# exit != 0 + anlaşılır hata
```

Kontroller:

- JSON geçerli ve `AgentState` şemasına uyuyor.
- `source_code` ve `findings` listeleri mevcut.
- Deterministik state’te `llm_summary` boş.
- Dosya izni `600`.
- İçerikte `CROWBAR_LLM_API_KEY`/`sk-` gibi key sızıntısı yok.
- Boyut makul (ör. `CROWBAR_HOST_MAX_STATE_MB`).

`tests/test_validate_state.py` ekle: geçerli fixture, bozuk JSON, izin hatası,
key sızıntısı senaryoları.

### 5. Host’a aktarım

Sadece state dosyalarını kopyala:

```bash
chmod 600 /out/*.state.json
# örnek: paylaşılan klasör / scp / USB
```

Host’ta:

```bash
./sandbox/run_host_analysis.sh /out/true.state.json /out/true.llm.json
```

Lokal model yoksa bunu raporda belirt; `host_analyze.py`’yi **0 fonksiyonlu**
bir state ile çalıştırıp CLI/şema yolunu yine de doğrula (LLM çağrısı olmaz).

### 6. Rapor

`sandbox/smoke_report.md` şablonu:

```md
# VM Smoke Report

- Tarih:
- Commit:
- VM / OS:
- Ghidra / capa / FLOSS / YARA / UPX sürümleri:
- Host modeli: (veya "LLM çalıştırılmadı")

## Sonuçlar

| Örnek | SHA256 | Fonksiyon | Finding | State KB | İzin | Host verdict | Süre | Hata |
|---|---|---:|---:|---:|---|---|---|---|
| true  | ... | ... | ... | ... | 600 | ... | ... | ... |
| ls    | ... | ... | ... | ... | 600 | ... | ... | ... |
| hello | ... | ... | ... | ... | 600 | ... | ... | ... |

## Bulunan sorunlar
- ...

## Çözülen sorunlar
- ...

## LLM çalıştırılmadıysa nedeni
- ...
```

## Kabul kriterleri

- [ ] 3/3 örnek için state üretildi.
- [ ] En az bir örnekte `source_code` ≥ 1 fonksiyon (Ghidra PATH’te).
- [ ] `validate_state.py` geçerli/bozuk/key/izin senaryolarını test ediyor.
- [ ] State dosyaları `600`; repoda state/sample yok.
- [ ] Host `state.llm.json` üretti (veya LLM’siz CLI yolu açıkça doğrulandı).
- [ ] `sandbox/smoke_report.md` dolduruldu; hatalar/timeout’lar dürüstçe yazıldı.
- [ ] Testler geçiyor: `pytest -q`.
- [ ] PR sadece rapor + script + testleri içeriyor.

## PR başlığı

`handoff: split-mode VM smoke validation`

## Sorular

- Ghidra `analyzeHeadless` PATH’te değilse: `GHIDRA_INSTALL_DIR` ayarla,
  sürümü raporla.
- Host’ta model yoksa: bulut key kullanma; raporu “LLM çalıştırılmadı” olarak
  işaretle ve `validate_state.py` + host CLI yolunu doğrula.
- Gerçek malware gerekiyorsa: **dur**, ayrı bir güvenlik planı olmadan devam etme.

## Referans

- [`sandbox/README.md`](../sandbox/README.md)
- [`README.md` — Split VM / host usage](../README.md#split-vm--host-usage-real-malware)

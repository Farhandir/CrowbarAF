# CrowbarAF — Kurulum

> Tam hat için dış araçlar gerekir. Hiçbiri kurulu değilse pipeline **çökmez**;
> ilgili düğüm boş sonuç döner ve log'a yazar (kademeli bozulma).

## 1. Python bağımlılıkları
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt          # çekirdek (langgraph, fastapi, pydantic...)
pip install -r requirements-tools.txt    # OPSİYONEL: capa, floss, yara-python, pyinstxtractor-ng
```

## 2. Ghidra + JDK + PyGhidra (native yol)
- **Ghidra 12.1.x** ve **JDK 21+** gerekir (JRE yetmez).
- `export_functions.py` **PyGhidra (Python 3)**; düz `analyzeHeadless` ile çalışmaz.
  `ghidra_runner.py` bunu `pyghidra_launcher.py -H` ile başlatır.
- **pyghidra** Python ortamında kurulu olmalı (Ghidra'nın içindeki wheel'den):
```bash
pip install --no-index -f "$GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/pypkg/dist" pyghidra
```

## 3. Sistem araçları (sudo)
```bash
sudo apt update
sudo apt install -y upx-ucl yara mono-complete        # upx, yara CLI, de4dot için mono
```

**Detect It Easy (diec):**
```bash
cd ~/Downloads
wget https://github.com/horsicq/DIE-engine/releases/download/3.21/die_3.21_Debian_12_amd64.deb
sudo apt install -y ./die_3.21_Debian_12_amd64.deb
diec --version        # die 3.21
```

**pycdc (PyInstaller .pyc decompile):**
```bash
git clone https://github.com/zrax/pycdc ~/.local/share/pycdc
cd ~/.local/share/pycdc && cmake . && make -j"$(nproc)"
ln -sf ~/.local/share/pycdc/pycdc ~/.local/bin/pycdc
```

## 4. Kural setleri
```bash
# capa kuralları (capa 10 gömülü kural içermez; -r ile verilir)
git clone --depth 1 https://github.com/mandiant/capa-rules ~/.local/share/capa-rules

# YARA kural dizini (CROWBAR_YARA_RULES)
mkdir -p ~/.local/share/crowbar/yara_rules
# .yar / .yara dosyalarını buraya koy
```

## 5. Ortam değişkenleri
```bash
cp .env.example .env
# düzenle ve: set -a; . ./.env; set +a
```

## 6. Doğrulama
```bash
for t in diec capa floss upx yara pycdc pyinstxtractor; do printf "%-16s " "$t"; command -v $t || echo YOK; done
```

## 7. Çalıştırma
```bash
python main.py <dosya>            # CLI: analiz + state JSON
python main.py --serve            # Web arayüzü/API: http://127.0.0.1:8000
python main.py --diagram          # Mermaid grafiği
```

## Kademeli bozulma (araç yoksa)
| Araç yok | Etki |
|---|---|
| `diec` | `sample.file_type/arch/packer` = `"unknown"`; route yine belirlenir |
| `yara`/`yara-python` | `yara_results=[]` |
| `capa` / kurallar | `capabilities` boş |
| `floss` | `extracted_strings` boş |
| `upx` | paket açılmaz, orijinal dosyayla devam |
| `pyinstxtractor`/`pycdc` | Python kaynağı çıkmaz → **native fallback** |
| `de4dot`/`ilspycmd` | .NET kaynağı çıkmaz → **native fallback** |
| Ghidra/JDK/pyghidra | `source_code=[]` → LLM katmanı "fonksiyon yok" der |

"""Ghidra analyzeHeadless orkestratörü (Python 3.12).

``export_functions.py`` betiğini (PyGhidra / Python 3) analyzeHeadless ile
çalıştırır. Betik dosyadaki tüm fonksiyonları puanlar, en yüksek puanlıları
decompile eder ve sonucu ``DecompiledFunction`` listesi olarak döndürür.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from typing import Any

from pydantic import BaseModel, ValidationError

from import_combos import combo_api_map
from state import DecompiledFunction

logger = logging.getLogger(__name__)

GHIDRA_TIMEOUT_SECONDS = 600  # 10 dakika
GHIDRA_PROJECT_NAME = "TempGhidraProject"
SCRIPT_NAME = "export_functions.py"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def _find_analyze_headless() -> str | None:
    """analyzeHeadless(.bat) yürütülebilirini PATH'te veya GHIDRA_INSTALL_DIR altında arar."""
    exe = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"

    found = shutil.which(exe)
    if found:
        return found

    install_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if install_dir:
        candidate = os.path.join(install_dir, "support", exe)
        if os.path.isfile(candidate):
            return candidate
    return None


def _finding_to_dict(finding: BaseModel | dict[str, Any]) -> dict[str, Any]:
    return finding.model_dump() if isinstance(finding, BaseModel) else dict(finding)


def run_ghidra(
    file_path: str,
    hints: list[dict[str, Any]],
    findings: list[BaseModel | dict[str, Any]] | None = None,
) -> list[DecompiledFunction]:
    """Hedef dosyayı Ghidra ile analiz eder; öncelikli fonksiyonları decompile eder.

    ``hints``: capa adres ipuçları (``[{"offset", "rule"}]``).
    ``findings``: ``state.findings``; betik ``import_combo`` bulgularını fonksiyon
    önceliğine yansıtmak için kullanır.

    ``hints`` ve ``findings`` boş olsa bile Ghidra çalıştırılır; betik tüm
    fonksiyonları tarayıp kendi önceliklendirmesini yapar. Hata, timeout veya
    Ghidra'nın bulunamaması durumunda çökmez; ``[]`` döndürür.
    """
    # TemporaryDirectory context manager yerine elle yönetilir: finally'de
    # temizlik garanti edilir ve Windows'ta kilitli dosyalar çökmeye yol açmaz.
    temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    try:
        analyze_headless = _find_analyze_headless()
        if analyze_headless is None:
            logger.error(
                "[run_ghidra] analyzeHeadless bulunamadı (PATH veya GHIDRA_INSTALL_DIR kontrol edin)"
            )
            return []

        temp_dir = temp.name
        input_json_path = os.path.join(temp_dir, "ghidra_input.json")
        out_json_path = os.path.join(temp_dir, "out.json")

        payload = {
            "hints": hints,
            "findings": [_finding_to_dict(f) for f in findings or []],
            # import_combo bulgusu -> API isimleri (betik kuralları bilmek zorunda kalmasın)
            "combo_apis": combo_api_map(),
        }
        with open(input_json_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=True)

        cmd = [
            analyze_headless,
            temp_dir,
            GHIDRA_PROJECT_NAME,
            "-import",
            file_path,
            # Betik varsayılan Ghidra script dizinlerinde olmadığı için gerekli
            "-scriptPath",
            SCRIPT_DIR,
            "-postScript",
            SCRIPT_NAME,
            input_json_path,
            out_json_path,
            "-deleteProject",
        ]

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=GHIDRA_TIMEOUT_SECONDS,
            check=False,
        )
        if proc.returncode != 0:
            tail = (proc.stderr.strip() or proc.stdout.strip() or "çıktı yok")[-500:]
            logger.error(
                "[run_ghidra] analyzeHeadless %s koduyla çıktı: %s", proc.returncode, tail
            )
            return []

        if not os.path.isfile(out_json_path):
            logger.error("[run_ghidra] Ghidra çıktı dosyası (out.json) üretmedi")
            return []

        with open(out_json_path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        if not isinstance(raw, list):
            logger.error("[run_ghidra] out.json beklenmeyen yapıda (liste değil)")
            return []

        functions: list[DecompiledFunction] = []
        for item in raw:
            try:
                functions.append(DecompiledFunction(**item))
            except (ValidationError, TypeError) as exc:
                logger.warning("[run_ghidra] geçersiz fonksiyon kaydı atlandı: %s", exc)
        return functions

    except subprocess.TimeoutExpired:
        logger.error("[run_ghidra] Ghidra %d saniye içinde tamamlanamadı (timeout)", GHIDRA_TIMEOUT_SECONDS)
    except FileNotFoundError as exc:
        logger.error("[run_ghidra] analyzeHeadless veya hedef dosya bulunamadı: %s", exc)
    except json.JSONDecodeError as exc:
        logger.error("[run_ghidra] out.json ayrıştırılamadı: %s", exc)
    except Exception as exc:  # noqa: BLE001 - iş akışı hiçbir koşulda çökmemeli
        logger.error("[run_ghidra] beklenmeyen hata: %s: %s", type(exc).__name__, exc)
    finally:
        temp.cleanup()  # temp klasör + ghidra_input.json/out.json mutlaka silinir

    return []

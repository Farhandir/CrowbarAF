"""LangGraph düğümleri (şimdilik stub).

Kurallar:
  * Her düğüm ``AgentState`` alır, sadece güncellenecek alanları ``dict`` olarak döndürür.
  * Dış araç (subprocess/CLI) entegrasyonu adım adım ekleniyor: şu an sadece capa hazır,
    diğerlerinin yerleri ``TODO`` ile işaretli.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from typing import Any

from state import AgentState, RouteFlag

logger = logging.getLogger(__name__)

CAPA_TIMEOUT_SECONDS = 300  # 5 dakika
FLOSS_TIMEOUT_SECONDS = 300  # 5 dakika

# YARA kuralının "kesin bilinen zararlı" sayılması için meta alanı (ör. meta: confidence = "known_malware")
KNOWN_MALWARE_META_KEY = "classification"
KNOWN_MALWARE_META_VALUE = "known_malware"


# --------------------------------------------------------------------------- #
# Yardımcı (saf) mantık: dış araç gerektirmez, test edilebilir.
# --------------------------------------------------------------------------- #
def decide_route(file_metadata: dict[str, Any], yara_results: list[dict[str, Any]]) -> RouteFlag:
    """DIE ve YARA sonuçlarına göre ``route_flag`` belirler."""
    for match in yara_results:
        meta = match.get("meta", {})
        if meta.get(KNOWN_MALWARE_META_KEY) == KNOWN_MALWARE_META_VALUE:
            return "fast_track"

    language = str(file_metadata.get("language", "")).lower()
    compiler = str(file_metadata.get("compiler", "")).lower()
    haystack = f"{language} {compiler}"

    if "python" in haystack or "pyinstaller" in haystack:
        return "python"
    if ".net" in haystack or "dotnet" in haystack or "c#" in haystack:
        return "dotnet"
    return "native"  # varsayılan: UPX vb. paketleyici kontrolü yapılacak yol


# --------------------------------------------------------------------------- #
# Ön tarama
# --------------------------------------------------------------------------- #
def entry_node(state: AgentState) -> dict[str, Any]:
    """DIE + YARA ön taraması yapar ve ``route_flag`` değerini belirler."""
    logger.info("[entry_node] %s", state.file_path)

    # TODO: DIE (diec --json) çalıştır -> file_metadata
    file_metadata: dict[str, Any] = dict(state.file_metadata)
    # TODO: YARA çalıştır -> yara_results
    yara_results: list[dict[str, Any]] = list(state.yara_results)

    return {
        "file_metadata": file_metadata,
        "yara_results": yara_results,
        "route_flag": decide_route(file_metadata, yara_results),
    }


# --------------------------------------------------------------------------- #
# Unpack düğümleri
# --------------------------------------------------------------------------- #
def unpack_python_node(state: AgentState) -> dict[str, Any]:
    """pyinstxtractor + pycdc."""
    logger.info("[unpack_python_node]")
    # TODO: pyinstxtractor ile .pyc çıkar, pycdc ile decompile et
    return {"source_code": dict(state.source_code)}


def unpack_dotnet_node(state: AgentState) -> dict[str, Any]:
    """de4dot (deobfuscation) + ILSpy (decompile)."""
    logger.info("[unpack_dotnet_node]")
    # TODO: de4dot ile temizle, ILSpy (ilspycmd) ile C# kodu üret
    return {"source_code": dict(state.source_code)}


def unpack_native_node(state: AgentState) -> dict[str, Any]:
    """UPX vb. paketleyicileri açar."""
    logger.info("[unpack_native_node]")
    # TODO: Paketleyiciye göre UPX (-d) vb. çalıştır, file_path'i açılmış dosyaya güncelle
    return {}


# --------------------------------------------------------------------------- #
# Statik analiz
# --------------------------------------------------------------------------- #
def static_feature_node(state: AgentState) -> dict[str, Any]:
    """FLOSS + capa."""
    logger.info("[static_feature_node]")

    floss_iocs = run_floss(state.file_path)  # hata durumunda []
    capabilities = run_capa(state.file_path)  # hata durumunda {"error": ...}

    return {
        # Mevcut değerlere ekle, tekilleştir
        "extracted_strings": _unique([*state.extracted_strings, *floss_iocs]),
        "capabilities": capabilities,
    }


# --------------------------------------------------------------------------- #
# FLOSS
# --------------------------------------------------------------------------- #
# Katı IoC filtresi: bir metin bu kalıplardan en az birine uymazsa elenir.
_IPV4_RE = re.compile(
    r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\d|\.\d)"
)
_URL_RE = re.compile(r"\b(?:https?|tcp)://[^\s'\"<>]+", re.IGNORECASE)
_FILE_EXT_RE = re.compile(
    r"[\w\-\\/:.$%]+\.(?:exe|dll|sys|bat|ps1|vbs|scr|lnk)(?![A-Za-z0-9])",
    re.IGNORECASE,
)
_REGISTRY_RE = re.compile(
    r"(?:\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)\\|Software\\Microsoft|SYSTEM\\CurrentControlSet)",
    re.IGNORECASE,
)
_IOC_PATTERNS = (_IPV4_RE, _URL_RE, _FILE_EXT_RE, _REGISTRY_RE)


def filter_iocs(strings_list: list[str]) -> list[str]:
    """IP, URL, dosya uzantısı veya registry yolu içeren metinleri tutar (tekilleştirilmiş)."""
    kept = [
        s
        for s in strings_list
        if isinstance(s, str) and s.strip() and any(p.search(s) for p in _IOC_PATTERNS)
    ]
    return _unique(kept)


def _collect_floss_strings(report: dict[str, Any]) -> list[str]:
    """FLOSS JSON'undan sadece decoded_strings ve stack_strings metinlerini toplar.

    ``static_strings`` bilinçli olarak alınmaz. Girdiler hem ``{"string": "..."}``
    nesnesi hem de düz string olabilir (FLOSS sürümüne göre).
    """
    strings_section = report.get("strings")
    if not isinstance(strings_section, dict):
        strings_section = report  # bazı sürümlerde anahtarlar kök seviyesinde olabilir

    pool: list[str] = []
    for key in ("decoded_strings", "stack_strings"):
        entries = strings_section.get(key)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            text = entry.get("string") if isinstance(entry, dict) else entry
            if isinstance(text, str):
                pool.append(text)
    return pool


def run_floss(file_path: str) -> list[str]:
    """``floss -j <file_path>`` çalıştırır; filtrelenmiş IoC metinlerini döndürür.

    Hata durumunda (zaman aşımı, floss/dosya bulunamadı, sıfır olmayan çıkış kodu,
    geçersiz JSON) uygulama çökmez; hata loglanır ve boş liste döndürülür.
    """
    try:
        proc = subprocess.run(
            ["floss", "-j", file_path],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=FLOSS_TIMEOUT_SECONDS,
            check=False,
        )
        if proc.returncode != 0:
            stderr = proc.stderr.strip() or "stderr boş"
            msg = f"floss {proc.returncode} koduyla çıktı: {stderr}"
        else:
            report = json.loads(proc.stdout)
            if not isinstance(report, dict):
                msg = "floss beklenmeyen JSON yapısı döndürdü (dict değil)"
            else:
                return filter_iocs(_collect_floss_strings(report))

    except subprocess.TimeoutExpired:
        msg = f"floss {FLOSS_TIMEOUT_SECONDS} saniye içinde tamamlanamadı (timeout)"
    except FileNotFoundError as exc:
        msg = f"floss veya hedef dosya bulunamadı: {exc}"
    except json.JSONDecodeError as exc:
        msg = f"floss çıktısı JSON olarak ayrıştırılamadı: {exc}"
    except Exception as exc:  # noqa: BLE001 - iş akışı hiçbir koşulda çökmemeli
        msg = f"floss çalıştırılırken beklenmeyen hata: {type(exc).__name__}: {exc}"

    logger.error("[static_feature_node] %s", msg)
    return []


def _unique(items: list[str]) -> list[str]:
    """Sırayı koruyarak tekilleştirir."""
    return list(dict.fromkeys(items))


def _format_capa_entry(entry: Any, kind: str) -> str | None:
    """capa ``meta.attack`` / ``meta.mbc`` girdisini okunabilir tek satıra çevirir.

    ATT&CK: "T1055.012 - Process Injection::Process Hollowing (Defense Evasion)"
    MBC:    "B0001.025 - Debugger Detection::Software Breakpoints (Anti-Behavioral Analysis)"

    Eski capa sürümlerindeki düz string girdiler olduğu gibi kabul edilir.
    """
    if isinstance(entry, str):
        return entry.strip() or None
    if not isinstance(entry, dict):
        return None

    ident = str(entry.get("id") or "").strip()
    if kind == "attack":
        group = str(entry.get("tactic") or "").strip()
        name = str(entry.get("technique") or "").strip()
        sub = str(entry.get("subtechnique") or "").strip()
    else:  # mbc
        group = str(entry.get("objective") or "").strip()
        name = str(entry.get("behavior") or "").strip()
        sub = str(entry.get("method") or "").strip()

    if sub:
        name = f"{name}::{sub}" if name else sub

    if not (ident or name):
        # Yapı beklenenden farklı: "parsed" listesine düş.
        parsed = entry.get("parsed")
        if isinstance(parsed, list) and parsed:
            return " :: ".join(str(p) for p in parsed)
        return None

    label = f"{ident} - {name}" if ident and name else (ident or name)
    return f"{label} ({group})" if group else label


def summarize_capa(report: dict[str, Any]) -> dict[str, list[str]]:
    """Ham capa JSON'unu LLM bağlamına uygun, küçük bir özete indirger.

    Sadece kural isimlerini, MITRE ATT&CK ve MBC girdilerini alır; ``matches``
    (mantık/eşleşme ağaçları) gibi büyük alanlar atılır. Beklenmeyen yapılarda
    hata fırlatmaz, ilgili kısmı atlar.
    """
    rules = report.get("rules")
    if not isinstance(rules, dict):
        rules = {}

    matched_rules: list[str] = []
    mitre_attack: list[str] = []
    malware_behavior: list[str] = []

    for rule_key, rule in rules.items():
        matched_rules.append(str(rule_key))

        meta = rule.get("meta") if isinstance(rule, dict) else None
        if not isinstance(meta, dict):
            continue

        for kind, target in (("attack", mitre_attack), ("mbc", malware_behavior)):
            entries = meta.get(kind)
            if not isinstance(entries, list):
                continue
            for entry in entries:
                label = _format_capa_entry(entry, kind)
                if label:
                    target.append(label)

    return {
        "matched_rules": _unique(matched_rules),
        "mitre_attack": _unique(mitre_attack),
        "malware_behavior": _unique(malware_behavior),
    }


def run_capa(file_path: str) -> dict[str, Any]:
    """``capa -j <file_path>`` çalıştırır ve çıktıyı özetlenmiş dict olarak döndürür.

    Başarıda: ``{"matched_rules": [...], "mitre_attack": [...], "malware_behavior": [...]}``
    Hata durumunda (zaman aşımı, capa/dosya bulunamadı, sıfır olmayan çıkış kodu,
    geçersiz JSON) uygulama çökmez; ``{"error": "<mesaj>"}`` döndürülür.
    """
    try:
        proc = subprocess.run(
            ["capa", "-j", file_path],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=CAPA_TIMEOUT_SECONDS,
            check=False,
        )
        if proc.returncode != 0:
            stderr = proc.stderr.strip() or "stderr boş"
            return {"error": f"capa {proc.returncode} koduyla çıktı: {stderr}"}

        result = json.loads(proc.stdout)
        if not isinstance(result, dict):
            return {"error": "capa beklenmeyen JSON yapısı döndürdü (dict değil)"}
        return summarize_capa(result)

    except subprocess.TimeoutExpired:
        msg = f"capa {CAPA_TIMEOUT_SECONDS} saniye içinde tamamlanamadı (timeout)"
    except FileNotFoundError as exc:
        msg = f"capa veya hedef dosya bulunamadı: {exc}"
    except json.JSONDecodeError as exc:
        msg = f"capa çıktısı JSON olarak ayrıştırılamadı: {exc}"
    except Exception as exc:  # noqa: BLE001 - iş akışı hiçbir koşulda çökmemeli
        msg = f"capa çalıştırılırken beklenmeyen hata: {type(exc).__name__}: {exc}"

    logger.error("[static_feature_node] %s", msg)
    return {"error": msg}


def deep_inspection_node(state: AgentState) -> dict[str, Any]:
    """Ghidra (headless) ile derin inceleme / decompile."""
    logger.info("[deep_inspection_node]")
    # TODO: analyzeHeadless ile capa'nın işaret ettiği fonksiyon offset'lerini decompile et
    return {"source_code": dict(state.source_code)}


# --------------------------------------------------------------------------- #
# AI ajanları (Ollama)
# --------------------------------------------------------------------------- #
def ai_extractor_agent(state: AgentState) -> dict[str, Any]:
    """FLOSS stringlerini temizler, IoC (IP, URL, domain, ...) çıkarır."""
    logger.info("[ai_extractor_agent]")
    # TODO: llm = get_llm(); stringleri süz ve yapılandırılmış IoC çıktısı al
    return {"iocs": dict(state.iocs)}


def ai_reverser_agent(state: AgentState) -> dict[str, Any]:
    """Decompile edilmiş kodu okuyup niyet tespiti yapar."""
    logger.info("[ai_reverser_agent]")
    # TODO: llm = get_llm(); source_code + capabilities üzerinden niyet analizi
    return {"intent_analysis": state.intent_analysis}


def ai_supervisor_agent(state: AgentState) -> dict[str, Any]:
    """Tüm verileri birleştirip nihai JSON/Markdown raporunu üretir."""
    logger.info("[ai_supervisor_agent]")
    # TODO: llm = get_llm(); tüm state'i sentezle
    return {"analysis_report": state.analysis_report}

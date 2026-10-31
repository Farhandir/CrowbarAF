"""LangGraph düğümleri (şimdilik stub).

Kurallar:
  * Her düğüm ``AgentState`` alır, sadece güncellenecek alanları ``dict`` olarak döndürür.
  * Dış araç (subprocess/CLI) entegrasyonu adım adım ekleniyor: şu an sadece capa hazır,
    diğerlerinin yerleri ``TODO`` ile işaretli.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import subprocess
import tempfile
from collections import Counter
from typing import Any

try:
    import pefile
except ImportError:  # kurulu değilse PE yardımcıları boş sonuç döner, akış çökmez
    pefile = None  # type: ignore[assignment]

import db
from ghidra_runner import run_ghidra
from import_combos import IMPORT_COMBO_RULES
from state import AgentState, DecompiledFunction, Finding, RouteFlag

logger = logging.getLogger(__name__)

CAPA_TIMEOUT_SECONDS = int(os.environ.get("CROWBAR_CAPA_TIMEOUT", "300"))
FLOSS_TIMEOUT_SECONDS = int(os.environ.get("CROWBAR_FLOSS_TIMEOUT", "300"))
DIE_TIMEOUT_SECONDS = int(os.environ.get("CROWBAR_DIE_TIMEOUT", "60"))
UPX_TIMEOUT_SECONDS = int(os.environ.get("CROWBAR_UPX_TIMEOUT", "60"))
UNPACKED_SUFFIX = ".unpacked"
CLEAN_SUFFIX = ".clean"  # de4dot çıktısı
PYTHON_TOOL_TIMEOUT_SECONDS = 60  # pyinstxtractor, pycdc/decompyle3
DOTNET_TOOL_TIMEOUT_SECONDS = 60  # de4dot
DOTNET_DECOMPILE_TIMEOUT_SECONDS = 120  # ilspycmd (büyük assembly'ler daha uzun sürer)
SHA256_CHUNK_SIZE = 1024 * 1024  # 1 MiB
YARA_RULES_ENV = "CROWBAR_YARA_RULES"  # run_yara'da rules_dir verilmezse kullanılır
CAPA_RULES_ENV = "CAPA_RULES"  # capa -r için kural dizini; boşsa capa'nın gömülü kuralları denenir

# YARA kuralının "kesin bilinen zararlı" sayılması için meta alanı (ör. meta: confidence = "known_malware")
KNOWN_MALWARE_META_KEY = "classification"
KNOWN_MALWARE_META_VALUE = "known_malware"


# --------------------------------------------------------------------------- #
# Yardımcı (saf) mantık: dış araç gerektirmez, test edilebilir.
# --------------------------------------------------------------------------- #
def decide_route(die_info: dict[str, Any], yara_results: list[dict[str, Any]]) -> RouteFlag:
    """DIE ve YARA sonuçlarına göre ``route_flag`` belirler.

    ``die_info``: ``run_die`` çıktısı (``packer``, ``language``, ``compiler``,
    ``detected`` vb.). Boş dict geçerlidir ve ``native`` yolunu verir.
    """
    for match in yara_results:
        meta = match.get("meta", {})
        if meta.get(KNOWN_MALWARE_META_KEY) == KNOWN_MALWARE_META_VALUE:
            return "fast_track"

    haystack = " ".join(
        str(die_info.get(key, "")) for key in ("language", "compiler", "packer", "detected")
    ).lower()

    if "python" in haystack or "pyinstaller" in haystack:
        return "python"
    if ".net" in haystack or "dotnet" in haystack or "c#" in haystack:
        return "dotnet"
    return "native"  # varsayılan: UPX vb. paketleyici kontrolü yapılacak yol


def compute_sha256(file_path: str) -> str:
    """Dosyanın SHA-256 özetini (hex) bellek dostu şekilde, parça parça okuyarak hesaplar.

    Dosya okunamazsa hata loglanır ve boş string döner.
    """
    digest = hashlib.sha256()
    try:
        with open(file_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(SHA256_CHUNK_SIZE), b""):
                digest.update(chunk)
    except OSError as exc:
        logger.error("[entry_node] sha256 hesaplanamadı: %s", exc)
        return ""
    return digest.hexdigest()


# --------------------------------------------------------------------------- #
# DIE (Detect It Easy)
# --------------------------------------------------------------------------- #
_ARCH_RE = re.compile(r"\b(AMD64|x86[-_]64|x64|I386|x86|ARM64|AARCH64|ARM|MIPS\d*|PPC\d*|RISCV\d*)\b", re.IGNORECASE)
_ARCH_NORMALIZE = {
    "amd64": "x86-64",
    "x86-64": "x86-64",
    "x86_64": "x86-64",
    "x64": "x86-64",
    "i386": "x86",
    "x86": "x86",
    "arm64": "arm64",
    "aarch64": "arm64",
    "arm": "arm",
}


def _normalize_file_type(raw: Any) -> str:
    """DIE ``filetype`` değerini (PE32, PE64, ELF64, ...) sözleşme biçimine indirger."""
    text = str(raw or "").strip()
    upper = text.upper()
    if upper.startswith("PE"):
        return "PE"
    if upper.startswith("ELF"):
        return "ELF"
    if upper.startswith("MACH"):
        return "Mach-O"
    return text or "unknown"


def _normalize_arch(raw: str) -> str | None:
    match = _ARCH_RE.search(raw)
    if not match:
        return None
    key = match.group(1).lower()
    return _ARCH_NORMALIZE.get(key, key)


def _parse_die_report(report: dict[str, Any]) -> dict[str, Any]:
    """Ham ``diec --json`` çıktısından sample/rota bilgilerini ayıklar (saf mantık).

    Dönüş anahtarları: ``file_type``, ``packer``, ``arch`` (varsa), ``compiler``,
    ``language`` (varsa) ve ``detected`` (tüm tespit isimleri, rota kararı için).
    Beklenmeyen yapıda ``{}`` döner. Paketleyici tespit edilmediyse ``packer`` = ``"none"``.
    """
    detects = report.get("detects")
    if not isinstance(detects, list) or not detects or not isinstance(detects[0], dict):
        return {}
    first = detects[0]

    result: dict[str, Any] = {"file_type": _normalize_file_type(first.get("filetype"))}
    packer = compiler = language = None
    arch = None
    detected: list[str] = []

    values = first.get("values")
    for value in values if isinstance(values, list) else []:
        if not isinstance(value, dict):
            continue
        name = str(value.get("name") or "").strip()
        vtype = str(value.get("type") or "").strip().lower()
        if name:
            detected.append(name)
            if vtype in ("packer", "protector") and packer is None:
                packer = name
            elif vtype == "compiler" and compiler is None:
                compiler = name
            elif vtype == "language" and language is None:
                language = name
        if arch is None:
            arch = _normalize_arch(f"{value.get('info', '')} {value.get('string', '')}")

    if arch is None:
        arch = _normalize_arch(str(first.get("info") or ""))

    result["packer"] = packer or "none"
    if arch:
        result["arch"] = arch
    if compiler:
        result["compiler"] = compiler
    if language:
        result["language"] = language
    result["detected"] = " ".join(detected)
    return result


def run_die(file_path: str) -> dict[str, Any]:
    """``diec --json <file_path>`` çalıştırır; ``file_type``/``arch``/``packer`` (+ compiler) döndürür.

    Araç yoksa, zaman aşımı, sıfır olmayan çıkış kodu veya geçersiz JSON durumunda
    çökmez; hata loglanır ve ``{}`` döndürülür.
    """
    try:
        proc = subprocess.run(
            ["diec", "--json", file_path],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=DIE_TIMEOUT_SECONDS,
            check=False,
        )
        if proc.returncode != 0:
            stderr = proc.stderr.strip() or "stderr boş"
            msg = f"diec {proc.returncode} koduyla çıktı: {stderr}"
        else:
            report = json.loads(proc.stdout)
            if isinstance(report, dict):
                return _parse_die_report(report)
            msg = "diec beklenmeyen JSON yapısı döndürdü (dict değil)"
    except subprocess.TimeoutExpired:
        msg = f"diec {DIE_TIMEOUT_SECONDS} saniye içinde tamamlanamadı (timeout)"
    except FileNotFoundError as exc:
        msg = f"diec veya hedef dosya bulunamadı: {exc}"
    except json.JSONDecodeError as exc:
        msg = f"diec çıktısı JSON olarak ayrıştırılamadı: {exc}"
    except Exception as exc:  # noqa: BLE001 - iş akışı hiçbir koşulda çökmemeli
        msg = f"diec çalıştırılırken beklenmeyen hata: {type(exc).__name__}: {exc}"

    logger.error("[entry_node] %s", msg)
    return {}


# --------------------------------------------------------------------------- #
# YARA
# --------------------------------------------------------------------------- #
def run_yara(file_path: str, rules_dir: str = "") -> list[dict[str, Any]]:
    """YARA kurallarını dosyaya uygular; ``[{"rule", "tags", "meta"}]`` döndürür.

    ``yara-python`` kurulu değilse veya kural dizini verilmemişse/bulunamazsa
    ``[]`` döner (stub davranışı). ``rules_dir`` boşsa ``CROWBAR_YARA_RULES``
    ortam değişkeni kullanılır.
    """
    rules_dir = rules_dir or os.environ.get(YARA_RULES_ENV, "")
    if not rules_dir:
        return []

    try:
        import yara  # type: ignore[import-not-found]
    except ImportError:
        logger.warning("[entry_node] yara-python kurulu değil; YARA taraması atlandı")
        return []

    try:
        sources = {
            os.path.splitext(name)[0]: os.path.join(rules_dir, name)
            for name in sorted(os.listdir(rules_dir))
            if name.lower().endswith((".yar", ".yara"))
        }
        if not sources:
            return []
        rules = yara.compile(filepaths=sources)
        return [
            {"rule": m.rule, "tags": list(m.tags), "meta": dict(m.meta)}
            for m in rules.match(file_path)
        ]
    except Exception as exc:  # noqa: BLE001 - iş akışı hiçbir koşulda çökmemeli
        logger.error("[entry_node] YARA hatası: %s: %s", type(exc).__name__, exc)
        return []


# --------------------------------------------------------------------------- #
# Ön tarama
# --------------------------------------------------------------------------- #
def entry_node(state: AgentState) -> dict[str, Any]:
    """SHA-256 + DIE + YARA ön taraması yapar; ``sample`` ve ``route_flag`` değerlerini belirler."""
    logger.info("[entry_node] %s", state.file_path)

    sha256 = compute_sha256(state.file_path)
    die_info = run_die(state.file_path)  # araç yoksa/hata durumunda {}
    yara_results = run_yara(state.file_path)  # kural/kütüphane yoksa []

    route = decide_route(die_info, yara_results)

    # DIE bilgi vermediyse SampleInfo varsayılanları ("unknown") korunur
    updated_sample = state.sample.model_copy(
        update={
            "sha256": sha256 or state.sample.sha256,
            "file_type": die_info.get("file_type", state.sample.file_type),
            "arch": die_info.get("arch", state.sample.arch),
            "packer": die_info.get("packer", state.sample.packer),
            "route": route,
        }
    )

    return {
        "sample": updated_sample,
        "route_flag": route,
        "yara_results": yara_results,
        # fast_track static_feature_node'u atlar; YARA kanıtı yine de findings'e girsin
        "findings": merge_findings(state.findings, yara_findings(yara_results)),
    }


# --------------------------------------------------------------------------- #
# Unpack düğümleri
# --------------------------------------------------------------------------- #
def _run_tool(cmd: list[str], timeout: int, cwd: str | None = None) -> subprocess.CompletedProcess[str] | None:
    """Harici aracı çalıştırır. Yalnızca ``returncode == 0`` ise sonucu döndürür; aksi halde ``None``.

    Araç yoksa, timeout olursa veya sıfır olmayan kodla çıkarsa hata loglanır; asla fırlatmaz.
    """
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            cwd=cwd,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.warning("[unpack] %s %d saniye içinde tamamlanamadı (timeout)", cmd[0], timeout)
        return None
    except FileNotFoundError as exc:
        logger.warning("[unpack] %s bulunamadı: %s", cmd[0], exc)
        return None
    except Exception as exc:  # noqa: BLE001 - iş akışı hiçbir koşulda çökmemeli
        logger.warning("[unpack] %s çalıştırılamadı: %s: %s", cmd[0], type(exc).__name__, exc)
        return None

    if proc.returncode != 0:
        tail = (proc.stderr.strip() or proc.stdout.strip() or "çıktı yok")[-300:]
        logger.warning("[unpack] %s %s koduyla çıktı: %s", cmd[0], proc.returncode, tail)
        return None
    return proc


def _find_main_pyc(extracted_dir: str, exe_stem: str, extractor_stdout: str) -> str | None:
    """pyinstxtractor çıktı klasöründeki uygulamanın ana ``.pyc`` dosyasını bulur.

    Sıra: (1) exe adıyla aynı olan, (2) pyinstxtractor'ın "Possible entry point"
    olarak bildirdiği, (3) en büyük uygulama .pyc'si. PyInstaller'ın kendi
    ``pyi*`` yardımcı betikleri her zaman elenir.
    """
    try:
        names = sorted(
            n
            for n in os.listdir(extracted_dir)
            if n.lower().endswith(".pyc")
            and not n.lower().startswith("pyi")
            and os.path.isfile(os.path.join(extracted_dir, n))
        )
    except OSError:
        return None

    for name in names:
        if os.path.splitext(name)[0].lower() == exe_stem.lower():
            return os.path.join(extracted_dir, name)
    for match in re.finditer(r"Possible entry point:\s*(\S+\.pyc)", extractor_stdout):
        if match.group(1) in names:
            return os.path.join(extracted_dir, match.group(1))
    if names:
        return os.path.join(extracted_dir, max(names, key=lambda n: os.path.getsize(os.path.join(extracted_dir, n))))
    return None


def _decompile_pyc(pyc_path: str) -> str:
    """``pycdc``, başarısız olursa ``decompyle3`` ile .pyc'yi Python kaynağına çevirir; yoksa ``""``."""
    for tool in ("pycdc", "decompyle3"):
        proc = _run_tool([tool, pyc_path], PYTHON_TOOL_TIMEOUT_SECONDS)
        if proc is not None and proc.stdout.strip():
            return proc.stdout
    return ""


def _extract_python_source(file_path: str) -> str:
    """PyInstaller exe'sinden ana betiğin Python kaynağını çıkarır; başarısızsa ``""``."""
    temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    try:
        abs_path = os.path.abspath(file_path)
        # pyinstxtractor çıktısını çalışma dizinine yazar: orijinal dosyanın yanını kirletmesin
        proc = _run_tool(["pyinstxtractor", abs_path], PYTHON_TOOL_TIMEOUT_SECONDS, cwd=temp.name)
        if proc is None:
            return ""

        base = os.path.basename(abs_path)
        extracted_dir = os.path.join(temp.name, base + "_extracted")
        if not os.path.isdir(extracted_dir):
            logger.warning("[unpack_python_node] pyinstxtractor çıktı klasörü bulunamadı: %s", extracted_dir)
            return ""

        pyc_path = _find_main_pyc(extracted_dir, os.path.splitext(base)[0], proc.stdout)
        if pyc_path is None:
            logger.warning("[unpack_python_node] ana .pyc dosyası bulunamadı")
            return ""
        return _decompile_pyc(pyc_path)
    except Exception as exc:  # noqa: BLE001 - iş akışı hiçbir koşulda çökmemeli
        logger.warning("[unpack_python_node] beklenmeyen hata: %s: %s", type(exc).__name__, exc)
        return ""
    finally:
        temp.cleanup()


def unpack_python_node(state: AgentState) -> dict[str, Any]:
    """pyinstxtractor + pycdc/decompyle3: PyInstaller exe'sinden Python kaynağı çıkarır.

    Rota ``python`` değilse ``{}`` döner. Herhangi bir adım başarısız olursa
    (araç yok, timeout, kaynak çıkmadı) ``{"route_flag": "native"}`` döner; böylece
    ``deep_inspection_node`` Ghidra'yı çalıştırabilir (native fallback).
    """
    logger.info("[unpack_python_node]")
    if state.sample.route != "python":
        return {}

    code = _extract_python_source(state.file_path)
    if not code.strip():
        logger.warning("[unpack_python_node] kaynak çıkarılamadı; native fallback")
        return {"route_flag": "native"}
    func = DecompiledFunction(offset="", name="main_script", priority=10, c_code=code)
    return {"source_code": [func]}


def _extract_dotnet_source(file_path: str) -> str:
    """de4dot ile temizleyip ilspycmd ile C# kaynağı üretir; başarısızsa ``""``."""
    clean_path = file_path + CLEAN_SUFFIX
    try:
        if os.path.exists(clean_path):
            os.remove(clean_path)  # önceki çalıştırmadan kalan çıktı

        if _run_tool(["de4dot", file_path, "-o", clean_path], DOTNET_TOOL_TIMEOUT_SECONDS) is None:
            return ""
        if not os.path.isfile(clean_path):
            logger.warning("[unpack_dotnet_node] de4dot çıktı dosyası üretmedi")
            return ""

        # Not: ``-p`` (proje modu) ``-o <klasör>`` gerektirir; stdout modu tek parça C# verir.
        proc = _run_tool(["ilspycmd", clean_path], DOTNET_DECOMPILE_TIMEOUT_SECONDS)
        return proc.stdout if proc is not None and proc.stdout.strip() else ""
    except Exception as exc:  # noqa: BLE001 - iş akışı hiçbir koşulda çökmemeli
        logger.warning("[unpack_dotnet_node] beklenmeyen hata: %s: %s", type(exc).__name__, exc)
        return ""
    finally:
        # Orijinal örneğin yanında artefakt bırakma (file_path değişmediği için gerekmiyor)
        try:
            if os.path.exists(clean_path):
                os.remove(clean_path)
        except OSError:
            pass


def unpack_dotnet_node(state: AgentState) -> dict[str, Any]:
    """de4dot (deobfuscation) + ilspycmd (decompile): .NET assembly'den C# kaynağı çıkarır.

    Rota ``dotnet`` değilse ``{}`` döner. Herhangi bir adım başarısız olursa
    (araç yok, timeout, kaynak çıkmadı) ``{"route_flag": "native"}`` döner; böylece
    ``deep_inspection_node`` Ghidra'yı çalıştırabilir (native fallback).
    """
    logger.info("[unpack_dotnet_node]")
    if state.sample.route != "dotnet":
        return {}

    code = _extract_dotnet_source(state.file_path)
    if not code.strip():
        logger.warning("[unpack_dotnet_node] kaynak çıkarılamadı; native fallback")
        return {"route_flag": "native"}
    func = DecompiledFunction(offset="", name="dotnet_source", priority=10, c_code=code)
    return {"source_code": [func]}


def unpack_native_node(state: AgentState) -> dict[str, Any]:
    """UPX paketli örnekleri açar; sonraki düğümler için ``file_path``'i günceller.

    Packer UPX değilse hiçbir şey yapmaz (``{}``). Unpack başarısız olursa
    (araç yok, timeout, bozuk başlık) çökmez; orijinal dosyayla devam edilir.
    ``sample.sha256`` orijinal dosyanın kimliğini korur (bu düğüm ona dokunmaz).
    """
    logger.info("[unpack_native_node]")

    if "upx" not in state.sample.packer.lower():
        return {}

    unpacked_path = state.file_path + UNPACKED_SUFFIX
    if _run_upx_unpack(state.file_path, unpacked_path):
        logger.info("[unpack_native_node] UPX açıldı: %s", unpacked_path)
        return {"file_path": unpacked_path}
    return {}


def _run_upx_unpack(src: str, dst: str) -> bool:
    """``upx -d -o <dst> <src>`` çalıştırır; başarıda ``True`` döner. Hata durumunda hiç fırlatmaz."""
    try:
        # UPX var olan çıktı dosyasının üzerine yazmayı reddeder; önceki çalıştırmadan kalanı temizle
        if os.path.exists(dst):
            os.remove(dst)

        proc = subprocess.run(
            ["upx", "-d", "-o", dst, src],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=UPX_TIMEOUT_SECONDS,
            check=False,
        )
        if proc.returncode == 0 and os.path.isfile(dst):
            return True
        stderr = (proc.stderr.strip() or proc.stdout.strip() or "çıktı yok")[-300:]
        msg = f"upx {proc.returncode} koduyla çıktı (veya çıktı dosyası yok): {stderr}"
    except subprocess.TimeoutExpired:
        msg = f"upx {UPX_TIMEOUT_SECONDS} saniye içinde tamamlanamadı (timeout)"
    except FileNotFoundError as exc:
        msg = f"upx bulunamadı: {exc}"
    except Exception as exc:  # noqa: BLE001 - iş akışı hiçbir koşulda çökmemeli
        msg = f"upx çalıştırılırken beklenmeyen hata: {type(exc).__name__}: {exc}"

    logger.warning("[unpack_native_node] %s; orijinal dosyayla devam ediliyor", msg)
    # Yarım kalmış çıktıyı bırakma
    try:
        if os.path.exists(dst):
            os.remove(dst)
    except OSError:
        pass
    return False


# --------------------------------------------------------------------------- #
# Statik analiz
# --------------------------------------------------------------------------- #
def static_feature_node(state: AgentState) -> dict[str, Any]:
    """FLOSS + capa + pefile (import/entropy); tüm bulguları ``findings`` altında toplar."""
    logger.info("[static_feature_node]")

    floss_iocs, floss_hints = run_floss_with_hints(state.file_path)  # hata: ([], [])
    # Hata/timeout durumunda: ({"error": ...}, [])
    capabilities, ghidra_hints = run_capa(state.file_path)
    capabilities, ghidra_hints = _filter_trivial_capa(capabilities, ghidra_hints)

    # Ham import listesi findings'e GİRMEZ (gürültü); yalnızca combo eşleşmesi ve imphash için kullanılır.
    imports = extract_imports(state.file_path)  # PE: pefile, ELF: readelf; aksi halde []
    imphash = compute_imphash(state.file_path, imports)  # PE: pefile imphash, ELF: MD5(imports); yoksa ""
    entropy = section_entropy(state.file_path)  # PE: pefile, ELF: readelf -S; aksi halde {}
    entropy_source = "elf_entropy" if is_elf(state.file_path) else "pefile_entropy"
    combos = match_import_combos(imports)

    # PE metadata: dosya tek kez yüklenir, üç yardımcıya aynı nesne verilir
    pe = _load_pe(state.file_path)
    pe_metadata: list[Finding] = []
    try:
        pe_metadata = pe_metadata_findings(pe)
    except Exception as exc:  # noqa: BLE001 - metadata hatası analizin geri kalanını düşürmemeli
        logger.warning("[static_feature_node] PE metadata okunamadı: %s: %s", type(exc).__name__, exc)
    finally:
        if pe is not None:
            pe.close()

    # Mevcut değerlere ekle, tekilleştir
    extracted_strings = _unique([*state.extracted_strings, *floss_iocs])

    new_findings = build_findings(
        yara_results=state.yara_results,
        capabilities=capabilities,
        ghidra_hints=ghidra_hints,
        import_combos=combos,
        entropy=entropy,
        ioc_strings=extracted_strings,
        imphash=imphash,
        entropy_source=entropy_source,
        pe_metadata=pe_metadata,
    )

    return {
        "extracted_strings": extracted_strings,
        "capabilities": capabilities,
        "ghidra_hints": ghidra_hints,
        "floss_hints": floss_hints,
        "findings": merge_findings(state.findings, new_findings),
    }


# --------------------------------------------------------------------------- #
# pefile: importlar, section entropy, import kombinasyonları
# --------------------------------------------------------------------------- #
HIGH_ENTROPY_THRESHOLD = 7.0
ELF_MAGIC = b"\x7fELF"
READELF_TIMEOUT_SECONDS = int(os.environ.get("CROWBAR_READELF_TIMEOUT", "30"))

# `readelf --wide --dyn-syms` satırı:
#   "    12: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND ptrace@GLIBC_2.2.5 (2)"
# Gruplar: (Type, Name). Ndx = UND olanlar dışarıdan (libc/ld.so) import edilen sembollerdir.
_READELF_UND_RE = re.compile(
    r"^\s*\d+:\s+[0-9A-Fa-f]+\s+\d+\s+(?P<type>\w+)\s+\w+\s+\w+\s+UND\s+(?P<name>\S+)"
)
# Veri sembolleri (stdout, environ...) ve NOTYPE zayıf sembolleri (__gmon_start__) fonksiyon import'u değildir.
_ELF_IMPORT_TYPES = frozenset({"FUNC", "IFUNC", "GNU_IFUNC"})


def is_elf(file_path: str) -> bool:
    """Dosyanın ilk 4 byte'ı ``\\x7fELF`` mi? Okunamıyorsa ``False``."""
    try:
        with open(file_path, "rb") as fh:
            return fh.read(len(ELF_MAGIC)) == ELF_MAGIC
    except OSError:
        return False


def parse_readelf_dynsyms(output: str) -> list[str]:
    """``readelf --wide --dyn-syms`` çıktısından UND fonksiyon isimlerini ayıklar (saf mantık).

    Sürüm eki (``@GLIBC_2.2.5``) atılır; tekilleştirilir, sıra korunur.
    """
    names: list[str] = []
    for line in output.splitlines():
        match = _READELF_UND_RE.match(line)
        if not match or match.group("type") not in _ELF_IMPORT_TYPES:
            continue
        name = match.group("name").split("@", 1)[0]
        if name:
            names.append(name)
    return _unique(names)


def extract_elf_imports(file_path: str) -> list[str]:
    """ELF dinamik sembol tablosundaki (UND) import edilen fonksiyon isimlerini döndürür.

    ``readelf`` yoksa, timeout olursa, sıfırdan farklı kodla çıkarsa veya başka bir hata olursa
    hata loglanır ve ``[]`` döner. Statik bağlı ELF'te dinamik sembol tablosu olmadığından ``[]`` döner.
    """
    cmd = ["readelf", "--wide", "--dyn-syms", file_path]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=READELF_TIMEOUT_SECONDS,
            check=False,
            env={**os.environ, "LC_ALL": "C"},  # sütun biçimi yerelden bağımsız olsun
        )
    except FileNotFoundError:
        logger.warning("[static_feature_node] readelf bulunamadı; ELF importları atlanıyor")
        return []
    except subprocess.TimeoutExpired:
        logger.warning("[static_feature_node] readelf %d saniye içinde bitmedi (timeout)", READELF_TIMEOUT_SECONDS)
        return []
    except Exception as exc:  # noqa: BLE001 - iş akışı hiçbir koşulda çökmemeli
        logger.warning("[static_feature_node] readelf çalıştırılamadı: %s: %s", type(exc).__name__, exc)
        return []

    if proc.returncode != 0:
        logger.warning(
            "[static_feature_node] readelf %d koduyla çıktı: %s", proc.returncode, (proc.stderr or "").strip()[:200]
        )
        return []
    return parse_readelf_dynsyms(proc.stdout or "")


def extract_imports(file_path: str) -> list[str]:
    """Dosyanın import ettiği API/fonksiyon isimlerini döndürür (tekilleştirilmiş, sıra korunur).

    * İlk 4 byte ``\\x7fELF`` ise ``readelf --wide --dyn-syms`` ile UND semboller (``extract_elf_imports``).
    * Aksi halde pefile ile PE import tablosu.

    Geçerli bir PE/ELF değilse, araç yoksa veya dosya okunamazsa ``[]`` döner.
    """
    if is_elf(file_path):
        return extract_elf_imports(file_path)
    if pefile is None:
        return []
    pe = None
    try:
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        names: list[str] = []
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            for imp in entry.imports:
                if imp.name:  # sadece ordinal ile içe aktarılanlar atlanır
                    names.append(imp.name.decode("utf-8", errors="replace"))
        return _unique(names)
    except pefile.PEFormatError:
        return []
    except Exception as exc:  # noqa: BLE001 - iş akışı hiçbir koşulda çökmemeli
        logger.warning("[static_feature_node] import okunamadı: %s: %s", type(exc).__name__, exc)
        return []
    finally:
        if pe is not None:
            pe.close()


PE_MAGIC = b"MZ"
ENTROPY_READ_CHUNK = 1024 * 1024  # 1 MiB

# `readelf -S -W` bölüm satırı:
#   "  [ 1] .interp           PROGBITS        00000000004002a8 0002a8 00001c 00   A  0   0  1"
# Gruplar: Nr, Name, Type, (Address), Off, Size  (Off/Size hex)
_READELF_SECTION_RE = re.compile(
    r"^\s*\[\s*(?P<nr>\d+)\]\s+(?P<name>\S+)\s+(?P<type>\S+)\s+[0-9A-Fa-f]+\s+"
    r"(?P<off>[0-9A-Fa-f]+)\s+(?P<size>[0-9A-Fa-f]+)\s"
)


def is_pe(file_path: str) -> bool:
    """Dosyanın ilk 2 byte'ı ``MZ`` mi? Okunamıyorsa ``False``."""
    try:
        with open(file_path, "rb") as fh:
            return fh.read(len(PE_MAGIC)) == PE_MAGIC
    except OSError:
        return False


def _entropy_from_counts(counts: Any, total: int) -> float:
    if total <= 0:
        return 0.0
    entropy = 0.0
    for count in counts:
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def shannon_entropy(data: bytes) -> float:
    """Bayt dizisinin Shannon entropy değeri (0.0 – 8.0). Boş veri için 0.0."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte, n in Counter(data).items():
        counts[byte] = n
    return _entropy_from_counts(counts, len(data))


def file_range_entropy(file_path: str, offset: int, size: int) -> float | None:
    """Dosyada ``offset``'ten ``size`` bayt okuyup Shannon entropy hesaplar.

    Büyük bölümlerde belleği şişirmemek için parça parça okunur. Okunabilen bayt yoksa
    (offset dosya dışında, ``size`` 0) veya dosya okunamıyorsa ``None``.
    """
    if offset < 0 or size <= 0:
        return None
    counts = [0] * 256
    total = 0
    try:
        with open(file_path, "rb") as fh:
            fh.seek(offset)
            remaining = size
            while remaining > 0:
                chunk = fh.read(min(ENTROPY_READ_CHUNK, remaining))
                if not chunk:
                    break
                for byte, n in Counter(chunk).items():
                    counts[byte] += n
                total += len(chunk)
                remaining -= len(chunk)
    except OSError:
        return None
    if total == 0:
        return None
    return _entropy_from_counts(counts, total)


def parse_readelf_sections(output: str) -> list[tuple[str, int, int]]:
    """``readelf -S -W`` çıktısından ``(ad, dosya_offset, boyut)`` listesi çıkarır (saf mantık).

    Offset/boyut hex'ten tam sayıya çevrilir. Dosyada yer kaplamayan bölümler (``NULL``, ``NOBITS``/.bss,
    Nr=0) ve boyutu 0 olanlar atlanır.
    """
    sections: list[tuple[str, int, int]] = []
    for line in output.splitlines():
        match = _READELF_SECTION_RE.match(line)
        if not match or match.group("nr") == "0" or match.group("type") in ("NULL", "NOBITS"):
            continue
        off, size = int(match.group("off"), 16), int(match.group("size"), 16)
        if size > 0:
            sections.append((match.group("name"), off, size))
    return sections


def _elf_section_entropy(file_path: str) -> dict[str, float]:
    """ELF bölümlerinin entropy değerleri (``readelf -S -W`` + dosyadan bayt okuma). Hata → ``{}``."""
    cmd = ["readelf", "-S", "-W", file_path]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=READELF_TIMEOUT_SECONDS,
            check=False,
            env={**os.environ, "LC_ALL": "C"},
        )
    except FileNotFoundError:
        logger.warning("[static_feature_node] readelf bulunamadı; ELF entropy atlanıyor")
        return {}
    except subprocess.TimeoutExpired:
        logger.warning("[static_feature_node] readelf -S %d saniye içinde bitmedi (timeout)", READELF_TIMEOUT_SECONDS)
        return {}
    except Exception as exc:  # noqa: BLE001 - iş akışı hiçbir koşulda çökmemeli
        logger.warning("[static_feature_node] readelf -S çalıştırılamadı: %s: %s", type(exc).__name__, exc)
        return {}
    if proc.returncode != 0:
        logger.warning("[static_feature_node] readelf -S %d koduyla çıktı", proc.returncode)
        return {}

    result: dict[str, float] = {}
    for name, off, size in parse_readelf_sections(proc.stdout or ""):
        value = file_range_entropy(file_path, off, size)
        if value is None:
            continue
        key, n = name, 1
        while key in result:
            n += 1
            key = f"{name}#{n}"
        result[key] = value
    return result


def compute_imphash(file_path: str, imports: list[str]) -> str:
    """Import özeti (aile gruplama anahtarı).

    * PE (``MZ``): ``pefile`` ``get_imphash()``; hata/pefile yok → ``""``.
    * ELF (``\\x7fELF``): ``md5(",".join(sorted(imports)))`` (import listesi boşsa ``""``). Sıralama,
      farklı bağlayıcı/derleyici sıralamalarında aynı import kümesinin aynı özeti vermesini sağlar.
    * Diğer dosyalar → ``""``.
    """
    if is_elf(file_path):
        names = sorted(n for n in imports if isinstance(n, str) and n)
        if not names:
            return ""
        return hashlib.md5(",".join(names).encode()).hexdigest()  # noqa: S324 - güvenlik amaçlı değil, gruplama anahtarı
    if is_pe(file_path):
        if pefile is None:
            return ""
        pe = None
        try:
            pe = pefile.PE(file_path, fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
            return pe.get_imphash() or ""
        except Exception as exc:  # noqa: BLE001 - iş akışı hiçbir koşulda çökmemeli
            logger.warning("[static_feature_node] imphash hesaplanamadı: %s: %s", type(exc).__name__, exc)
            return ""
        finally:
            if pe is not None:
                pe.close()
    return ""


def section_entropy(file_path: str) -> dict[str, float]:
    """Section'ların Shannon entropy değerlerini döndürür: ``{".text": 6.2, ...}``.

    * ELF (``\\x7fELF``): ``readelf -S -W`` ile bölüm offset/boyutu, dosyadan okunan baytlar üzerinden hesap.
    * Aksi halde pefile ile PE section'ları.

    Aynı isimli section'lar ``name#2`` biçiminde ayrıştırılır. Geçerli PE/ELF değilse ``{}``.
    """
    if is_elf(file_path):
        return _elf_section_entropy(file_path)
    if pefile is None:
        return {}
    pe = None
    try:
        pe = pefile.PE(file_path, fast_load=True)
        result: dict[str, float] = {}
        for section in pe.sections:
            name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace") or "<unnamed>"
            key, n = name, 1
            while key in result:
                n += 1
                key = f"{name}#{n}"
            result[key] = float(section.get_entropy())
        return result
    except pefile.PEFormatError:
        return {}
    except Exception as exc:  # noqa: BLE001 - iş akışı hiçbir koşulda çökmemeli
        logger.warning("[static_feature_node] entropy hesaplanamadı: %s: %s", type(exc).__name__, exc)
        return {}
    finally:
        if pe is not None:
            pe.close()


# --------------------------------------------------------------------------- #
# PE metadata: Authenticode varlığı, versiyon bilgisi, manifest ayrıcalık seviyesi
# --------------------------------------------------------------------------- #
RT_MANIFEST = 24
_DEFAULT_SECURITY_DIRECTORY_INDEX = 4  # IMAGE_DIRECTORY_ENTRY_SECURITY
# Çıktı sırası bu listeyle belirlenir
PE_VERSION_KEYS = (
    "OriginalFilename",
    "CompanyName",
    "FileDescription",
    "LegalCopyright",
    "ProductName",
    "FileVersion",
)
PE_VERSION_VALUE_MAX = 200  # örnekten gelen değer: bağlamı şişirmesin
# Windows'un kabul ettiği tek üç değer; örnekten gelen başka bir metin bulguya girmez.
_EXECUTION_LEVELS = {
    "asinvoker": "asInvoker",
    "highestavailable": "highestAvailable",
    "requireadministrator": "requireAdministrator",
}
_EXECUTION_LEVEL_RE = re.compile(
    r"<(?:\w+:)?requestedExecutionLevel\b[^>]*?\blevel\s*=\s*[\"']([^\"']*)[\"']", re.IGNORECASE
)


def _load_pe(file_path: str) -> Any | None:
    """Dosyayı pefile ile TEK kez yükler (import + resource dizinleri ayrıştırılmış).

    ELF, geçersiz PE (``PEFormatError``), okunamayan dosya veya ``pefile`` yoksa ``None``.
    Dönen nesneyi çağıran kapatmalıdır (``pe.close()``).
    """
    if pefile is None or is_elf(file_path):
        return None
    pe = None
    try:
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
            ]
        )
        return pe
    except Exception as exc:  # noqa: BLE001 - PEFormatError dahil; iş akışı hiçbir koşulda çökmemeli
        if pe is not None:
            pe.close()
        if type(exc).__name__ != "PEFormatError":  # PE olmayan dosya beklenen durum; sessiz geç
            logger.warning("[static_feature_node] PE yüklenemedi: %s: %s", type(exc).__name__, exc)
        return None


def check_authenticode(pe: Any) -> bool:
    """Güvenlik (sertifika) veri dizininin ``VirtualAddress`` değeri 0'dan büyükse ``True``.

    Bu yalnızca imzanın **varlığını** söyler; geçerliliği doğrulanmaz. Hata durumunda ``False``.
    """
    try:
        index = pefile.DIRECTORY_ENTRY.get("IMAGE_DIRECTORY_ENTRY_SECURITY", _DEFAULT_SECURITY_DIRECTORY_INDEX)
        directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        return index < len(directories) and directories[index].VirtualAddress > 0
    except Exception as exc:  # noqa: BLE001
        logger.debug("[static_feature_node] authenticode okunamadı: %s: %s", type(exc).__name__, exc)
        return False


def _to_text(value: Any) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return str(value).replace("\x00", "").strip()


def extract_pe_version_info(pe: Any) -> list[str]:
    """``StringFileInfo`` değerlerini ``["OriginalFilename: calc.exe", ...]`` olarak döndürür.

    Yalnızca ``PE_VERSION_KEYS`` içindeki alanlar alınır (sıra sabit), boş değerler atlanır, her değer
    ``PE_VERSION_VALUE_MAX`` karakterle sınırlanır. Versiyon bilgisi yoksa veya hata olursa ``[]``.
    """
    try:
        values: dict[str, str] = {}
        for info in getattr(pe, "FileInfo", None) or []:
            # Yeni pefile: FileInfo = [[entry, ...], ...]; eski sürümler düz liste verebilir
            for entry in info if isinstance(info, (list, tuple)) else [info]:
                if _to_text(getattr(entry, "Key", b"")) != "StringFileInfo":
                    continue
                for table in getattr(entry, "StringTable", None) or []:
                    for raw_key, raw_value in (getattr(table, "entries", None) or {}).items():
                        key, value = _to_text(raw_key), _to_text(raw_value)
                        if key in PE_VERSION_KEYS and value and key not in values:
                            values[key] = value[:PE_VERSION_VALUE_MAX]
        return [f"{key}: {values[key]}" for key in PE_VERSION_KEYS if key in values]
    except Exception as exc:  # noqa: BLE001
        logger.debug("[static_feature_node] versiyon bilgisi okunamadı: %s: %s", type(exc).__name__, exc)
        return []


def _decode_manifest(raw: bytes) -> str:
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")


def parse_execution_level(manifest_xml: str) -> str:
    """Manifest XML'inden ``requestedExecutionLevel level="..."`` değerini çıkarır.

    Yalnızca Windows'un tanıdığı değerler (asInvoker, highestAvailable, requireAdministrator) döner;
    başka bir metin veya eşleşme yoksa ``""``.
    """
    match = _EXECUTION_LEVEL_RE.search(manifest_xml or "")
    return _EXECUTION_LEVELS.get(match.group(1).strip().lower(), "") if match else ""


def extract_pe_manifest(pe: Any) -> str:
    """RT_MANIFEST (tip 24) kaynağındaki ``requestedExecutionLevel`` değerini döndürür.

    Kaynak dizini, manifest veya seviye yoksa ya da hata olursa ``""``.
    """
    try:
        resources = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
        if resources is None:
            return ""
        for type_entry in getattr(resources, "entries", None) or []:
            if getattr(type_entry, "id", None) != RT_MANIFEST:
                continue
            for name_entry in type_entry.directory.entries:
                for lang_entry in name_entry.directory.entries:
                    data = lang_entry.data.struct
                    level = parse_execution_level(_decode_manifest(pe.get_data(data.OffsetToData, data.Size)))
                    if level:
                        return level
        return ""
    except Exception as exc:  # noqa: BLE001
        logger.debug("[static_feature_node] manifest okunamadı: %s: %s", type(exc).__name__, exc)
        return ""


def pe_metadata_findings(pe: Any) -> list[Finding]:
    """Yüklü ``pe`` nesnesinden (yeniden I/O yapmadan) ``pe_metadata`` bulgularını üretir."""
    if pe is None:
        return []
    findings: list[Finding] = []
    if check_authenticode(pe):
        findings.append(Finding(source="pe_metadata", kind="authenticode", value="Present (Unverified)"))
    version = extract_pe_version_info(pe)
    if version:
        findings.append(Finding(source="pe_metadata", kind="version_info", value="; ".join(version)))
    privilege = extract_pe_manifest(pe)
    if privilege:
        findings.append(Finding(source="pe_metadata", kind="manifest_privilege", value=privilege))
    return findings


def match_import_combos(imports: list[str]) -> list[str]:
    """Şüpheli import kombinasyonlarını döndürür (büyük/küçük harf duyarsız).

    Örn. VirtualAlloc + WriteProcessMemory + CreateRemoteThread -> ``["Process Injection Combo"]``.
    """
    present = {name.lower() for name in imports if isinstance(name, str)}
    return [
        rule
        for rule, groups in IMPORT_COMBO_RULES.items()
        if all(any(api in present for api in group) for group in groups)
    ]


# --------------------------------------------------------------------------- #
# findings
# --------------------------------------------------------------------------- #
def _ioc_kind(text: str) -> str:
    """FLOSS IoC metninin türünü belirler: url | ip | registry | file."""
    if _URL_RE.search(text):
        return "url"
    if _IPV4_RE.search(text):
        return "ip"
    if _REGISTRY_RE.search(text):
        return "registry"
    return "file"


def yara_findings(yara_results: list[dict[str, Any]]) -> list[Finding]:
    return [
        Finding(source="yara", kind="rule", value=str(match["rule"]))
        for match in yara_results
        if isinstance(match, dict) and match.get("rule")
    ]


TRIVIAL_CAPA_RULES = {"contain loop"}


def _capa_is_trivial(rule) -> bool:
    return str(rule).strip().lower() in TRIVIAL_CAPA_RULES


def _filter_trivial_capa(capabilities, hints):
    caps = dict(capabilities or {})
    caps["matched_rules"] = [r for r in (caps.get("matched_rules") or [])
                             if not _capa_is_trivial(r)]
    kept = [h for h in (hints or []) if not _capa_is_trivial(h.get("rule", ""))]
    return caps, kept


def build_findings(
    *,
    yara_results: list[dict[str, Any]],
    capabilities: dict[str, Any],
    ghidra_hints: list[dict[str, Any]],
    import_combos: list[str],
    entropy: dict[str, float],
    ioc_strings: list[str],
    imphash: str = "",
    entropy_source: str = "pefile_entropy",
    pe_metadata: list[Finding] | None = None,
) -> list[Finding]:
    """Araç çıktılarını ``Finding`` listesine çevirir (saf mantık).

    Sıra, bağlam bütçesi daraldığında en değerli kanıtlar önde kalsın diye:
    yara, capa, import combo, imphash, entropy, floss.
    Ham import listesi bilerek bulgu üretmez; yalnızca eşleşen combolar ve ``imphash`` gider.
    ``entropy_source``: PE için ``pefile_entropy``, ELF için ``elf_entropy``.
    """
    findings: list[Finding] = yara_findings(yara_results)

    # capa: adresli eşleşmeler (ghidra_hints) + adresi olmayan kurallar + ATT&CK/MBC
    hints = [h for h in ghidra_hints
             if isinstance(h, dict) and h.get("rule") and not _capa_is_trivial(h["rule"])]
    hinted_rules = {str(h["rule"]) for h in hints}
    for hint in hints:
        findings.append(
            Finding(source="capa", kind="rule", value=str(hint["rule"]), address=str(hint.get("offset") or ""))
        )
    for rule in capabilities.get("matched_rules", []) or []:
        if str(rule) in hinted_rules or _capa_is_trivial(rule):
            continue
        findings.append(Finding(source="capa", kind="rule", value=str(rule)))
    for tech in capabilities.get("mitre_attack", []) or []:
        findings.append(Finding(source="capa", kind="attack", value=str(tech)))
    for behavior in capabilities.get("malware_behavior", []) or []:
        findings.append(Finding(source="capa", kind="behavior", value=str(behavior)))

    for combo in import_combos:
        findings.append(Finding(source="import_combo", kind="behavior", value=combo))

    if imphash:
        findings.append(Finding(source="imphash", kind="grouping_key", value=imphash))

    findings.extend(pe_metadata or [])

    for name, value in entropy.items():
        if value > HIGH_ENTROPY_THRESHOLD:
            findings.append(Finding(source=entropy_source, kind="high_entropy", value=f"{name}: {value:.2f}"))

    for text in ioc_strings:
        if isinstance(text, str) and text.strip():
            findings.append(Finding(source="floss", kind=_ioc_kind(text), value=text))

    return findings


def merge_findings(existing: list[Finding], new: list[Finding]) -> list[Finding]:
    """Mevcut bulgulara yenilerini ekler; (source, kind, value, address) bazında tekilleştirir."""
    seen: set[tuple[str, str, str, str]] = set()
    merged: list[Finding] = []
    for f in [*existing, *new]:
        key = (f.source, f.kind, f.value, f.address)
        if key not in seen:
            seen.add(key)
            merged.append(f)
    return merged


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
    """FLOSS JSON'undan decoded, stack, tight ve static string metinlerini toplar.

    ``run_floss`` çıktıyı ``filter_iocs`` ile süzdüğü için static string'lerin
    gürültüsü gelmez; düz metin C2 URL'leri ancak bu yolla bulguya girer.
    Girdiler hem ``{"string": "..."}`` nesnesi hem de düz string olabilir.
    """
    strings_section = report.get("strings")
    if not isinstance(strings_section, dict):
        strings_section = report  # bazı sürümlerde anahtarlar kök seviyesinde olabilir

    pool: list[str] = []
    for key in ("decoded_strings", "stack_strings", "tight_strings", "static_strings"):
        entries = strings_section.get(key)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            text = entry.get("string") if isinstance(entry, dict) else entry
            if isinstance(text, str):
                pool.append(text)
    return pool


def _collect_floss_hints(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Decoded/tight/stack string'lerin fonksiyon/adres metadata'sını toplar.

    ``function`` (tight/stack), ``decoded_at`` (decoded), ``program_counter`` ve
    ``address`` alanlarından hangisi varsa saklanır. Sadece IoC filtrenden geçen
    değerler döner; böylece gürültü artmaz.
    """
    strings_section = report.get("strings")
    if not isinstance(strings_section, dict):
        strings_section = report

    out: list[dict[str, Any]] = []
    seen: set[tuple] = set()
    for key in ("decoded_strings", "tight_strings", "stack_strings"):
        entries = strings_section.get(key)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            text = entry.get("string")
            if not isinstance(text, str) or not text.strip():
                continue
            if not filter_iocs([text]):
                continue
            hint: dict[str, Any] = {"value": text}
            for field in ("function", "decoded_at", "program_counter", "address"):
                if entry.get(field) is not None:
                    hint[field] = entry[field]
            if len(hint) == 1:  # no address/function metadata
                continue
            keyt = tuple(sorted(hint.items()))
            if keyt in seen:
                continue
            seen.add(keyt)
            out.append(hint)
    return out


def _filter_hints_by_iocs(hints: list[dict[str, Any]], iocs: list[str]) -> list[dict[str, Any]]:
    allowed = set(iocs)
    return [h for h in hints if h.get("value") in allowed]


def run_floss_with_hints(file_path: str) -> tuple[list[str], list[dict[str, Any]]]:
    """``floss -j`` çalıştırır; (filtrelenmiş IoC'ler, decoded-string hints) döndürür.

    Hata durumunda ``([], [])`` döner; akış çökmez.
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
                iocs = filter_iocs(_collect_floss_strings(report))
                hints = _filter_hints_by_iocs(_collect_floss_hints(report), iocs)
                return iocs, hints
    except subprocess.TimeoutExpired:
        msg = f"floss {FLOSS_TIMEOUT_SECONDS} saniye içinde tamamlanamadı (timeout)"
    except FileNotFoundError as exc:
        msg = f"floss veya hedef dosya bulunamadı: {exc}"
    except json.JSONDecodeError as exc:
        msg = f"floss çıktısı JSON olarak ayrıştırılamadı: {exc}"
    except Exception as exc:  # noqa: BLE001 - iş akışı hiçbir koşulda çökmemeli
        msg = f"floss çalıştırılırken beklenmeyen hata: {type(exc).__name__}: {exc}"

    logger.error("[static_feature_node] %s", msg)
    return [], []


def run_floss(file_path: str) -> list[str]:
    """Backward-compatible wrapper: only the filtered IoC strings."""
    return run_floss_with_hints(file_path)[0]


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


def _parse_capa_address(raw: Any) -> int | None:
    """capa adres temsillerini (farklı sürümler) tek bir int sanal adrese çevirir.

    Desteklenen biçimler:
      * ``{"type": "absolute", "value": 4198400}`` (capa >= 5/7)
      * ``["absolute", 4198400]`` (ara sürümler)
      * ``4198400`` / ``"4198400"`` / ``"0x401000"`` (eski sürümler)

    Spesifik bir bellek adresi olmayanlar (``file``, ``no address``, ``relative``,
    ``token`` vb. tipler) için ``None`` döner.
    """
    value: Any = raw
    if isinstance(raw, dict):
        if raw.get("type") != "absolute":
            return None
        value = raw.get("value")
    elif isinstance(raw, (list, tuple)):
        if len(raw) != 2 or raw[0] != "absolute":
            return None
        value = raw[1]

    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str):
        text = value.strip().lower()
        try:
            return int(text, 16) if text.startswith("0x") else int(text, 10)
        except ValueError:
            return None
    return None


def _rule_match_addresses(rule: dict[str, Any]) -> list[int]:
    """Bir capa kuralının ``matches`` / ``locations`` yapısındaki adresleri toplar."""
    addresses: list[int] = []

    def add(raw: Any) -> None:
        addr = _parse_capa_address(raw)
        if addr is not None:
            addresses.append(addr)

    matches = rule.get("matches")
    if isinstance(matches, dict):
        # Eski sürümler: {"<adres>": {...eşleşme ağacı...}}
        for key in matches:
            add(key)
    elif isinstance(matches, list):
        # Yeni sürümler: [[<adres>, {...eşleşme ağacı...}], ...]
        for item in matches:
            if isinstance(item, (list, tuple)) and item:
                add(item[0])

    locations = rule.get("locations")
    if isinstance(locations, list):
        for loc in locations:
            add(loc)

    return addresses


def _is_file_scope(meta: dict[str, Any]) -> bool:
    """Kural dosya seviyesinde (global) mi eşleşiyor?"""
    scope = meta.get("scope")
    if scope is None:
        scopes = meta.get("scopes")
        scope = scopes.get("static") if isinstance(scopes, dict) else None
    return isinstance(scope, str) and scope.strip().lower() == "file"


def extract_ghidra_hints(report: dict[str, Any]) -> list[dict[str, str]]:
    """Ham capa JSON'undan Ghidra'ya iletilecek hedef adresleri çıkarır.

    Dönüş: ``[{"offset": "0x401000", "rule": "encrypt data using AES"}, ...]``
    ``(offset, rule)`` çiftleri tekilleştirilir. Dosya seviyesinde (global)
    eşleşen veya spesifik bir bellek adresi olmayan kurallar atlanır.
    Beklenmeyen yapılarda hata fırlatmaz, ilgili kısmı atlar.
    """
    rules = report.get("rules")
    if not isinstance(rules, dict):
        return []

    hints: dict[tuple[str, str], dict[str, str]] = {}
    for rule_key, rule in rules.items():
        if not isinstance(rule, dict):
            continue
        meta = rule.get("meta")
        if isinstance(meta, dict) and _is_file_scope(meta):
            continue

        rule_name = str(rule_key)
        for addr in _rule_match_addresses(rule):
            offset = hex(addr)
            hints.setdefault(
                (offset, rule_name), {"offset": offset, "rule": rule_name}
            )

    return sorted(hints.values(), key=lambda h: (int(h["offset"], 16), h["rule"]))


def run_capa(file_path: str) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """``capa -j <file_path>`` çalıştırır; ``(özet, ghidra_hints)`` ikilisi döndürür.

    Başarıda:
      * özet: ``{"matched_rules": [...], "mitre_attack": [...], "malware_behavior": [...]}``
      * ghidra_hints: ``[{"offset": "0x401000", "rule": "..."}, ...]``
    Hata durumunda (zaman aşımı, capa/dosya bulunamadı, sıfır olmayan çıkış kodu,
    geçersiz JSON) uygulama çökmez; ``({"error": "<mesaj>"}, [])`` döndürülür.
    """
    try:
        # capa 10 gömülü kural içermez; kural dizini env'den verilir (yoksa capa kendi hatasını döndürür)
        rules = os.environ.get(CAPA_RULES_ENV, "")
        cmd = ["capa", "-j"]
        if rules:
            cmd += ["-r", rules]
        cmd.append(file_path)
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=CAPA_TIMEOUT_SECONDS,
            check=False,
        )
        if proc.returncode != 0:
            stderr = proc.stderr.strip() or "stderr boş"
            return {"error": f"capa {proc.returncode} koduyla çıktı: {stderr}"}, []

        result = json.loads(proc.stdout)
        if not isinstance(result, dict):
            return {"error": "capa beklenmeyen JSON yapısı döndürdü (dict değil)"}, []
        return summarize_capa(result), extract_ghidra_hints(result)

    except subprocess.TimeoutExpired:
        msg = f"capa {CAPA_TIMEOUT_SECONDS} saniye içinde tamamlanamadı (timeout)"
    except FileNotFoundError as exc:
        msg = f"capa veya hedef dosya bulunamadı: {exc}"
    except json.JSONDecodeError as exc:
        msg = f"capa çıktısı JSON olarak ayrıştırılamadı: {exc}"
    except Exception as exc:  # noqa: BLE001 - iş akışı hiçbir koşulda çökmemeli
        msg = f"capa çalıştırılırken beklenmeyen hata: {type(exc).__name__}: {exc}"

    logger.error("[static_feature_node] %s", msg)
    return {"error": msg}, []


def deep_inspection_node(state: AgentState) -> dict[str, Any]:
    """Ghidra (headless) ile derin inceleme / decompile.

    capa hint'leri ve ``state.findings`` (import combo vb.) Ghidra'ya öncelik
    puanlaması için iletilir. Hata/timeout durumunda ``run_ghidra`` ``[]`` döner.

    Ghidra koruyucusu: unpack düğümleri kaynak kodu zaten çıkardıysa
    (``source_code`` dolu) veya rota ``native`` değilse Ghidra çalıştırılmaz;
    böylece Python/C# kaynağı decompile çıktısıyla ezilmez.
    """
    logger.info("[deep_inspection_node]")
    if state.source_code or state.route_flag != "native":
        logger.info(
            "[deep_inspection_node] atlandı (source_code=%d, route_flag=%s)",
            len(state.source_code),
            state.route_flag,
        )
        return {}

    result = run_ghidra(state.file_path, state.ghidra_hints, state.findings,
                        decoded_hints=list(getattr(state, "floss_hints", []) or []))
    return {"source_code": result}


# --------------------------------------------------------------------------- #
# AI ajanları (Ollama)
# --------------------------------------------------------------------------- #
def ai_extractor_agent(state: AgentState) -> dict[str, Any]:
    """FLOSS stringlerini temizler, IoC (IP, URL, domain, ...) çıkarır."""
    logger.info("[ai_extractor_agent]")
    # IoC cikarimi deterministik yapilir (filter_iocs); LLM'e birakilmaz.
    iocs = dict(state.iocs)
    iocs.setdefault("ioc", _unique([s for s in state.extracted_strings if filter_iocs([s])]))
    return {"iocs": iocs}


def ai_reverser_agent(state: AgentState) -> dict[str, Any]:
    """Decompile edilmiş kodu okuyup niyet tespiti yapar (LLM katmanı)."""
    logger.info("[ai_reverser_agent]")
    from llm_layer.nodes import run_reverser
    return run_reverser(state)


def ai_supervisor_agent(state: AgentState) -> dict[str, Any]:
    """Tüm verileri birleştirip nihai JSON/Markdown raporunu üretir."""
    logger.info("[ai_supervisor_agent]")
    from llm_layer.nodes import run_supervisor
    return run_supervisor(state)


# --------------------------------------------------------------------------- #
# Kalıcılık
# --------------------------------------------------------------------------- #
def db_writer_node(state: AgentState) -> dict[str, Any]:
    """Analiz sonuçlarını SQLite'a yazar (samples, findings, functions, calls, llm_claims).

    ``sample.sha256`` boşsa (dosya okunamadı) hiçbir şey yazılmaz. Veritabanı
    hataları akışı çökertmez; loglanır. State değiştirilmez (``{}``).
    """
    logger.info("[db_writer_node]")
    sha256 = state.sample.sha256
    if not sha256:
        logger.warning("[db_writer_node] sha256 boş; veritabanına yazılmadı")
        return {}

    try:
        db_path = db.init_db()
        db.insert_sample(state.sample, db_path)
        db.insert_findings(sha256, state.findings, db_path)
        # llm_summary: DecompiledFunction.llm_summary (ai_reverser state'e geri yazar) -> functions.llm_summary
        db.insert_functions_and_calls(sha256, state.source_code, db_path)
        if state.analysis_report or state.verdict:  # supervisor raporu ve/veya dosya kararı
            db.insert_llm_claims(sha256, state.analysis_report, db_path, verdict=state.verdict)
    except Exception as exc:  # noqa: BLE001 - kalıcılık hatası analiz sonucunu düşürmemeli
        logger.error("[db_writer_node] veritabanı hatası: %s: %s", type(exc).__name__, exc)
    return {}

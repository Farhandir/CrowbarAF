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
import os
import re
import subprocess
import tempfile
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

CAPA_TIMEOUT_SECONDS = 300  # 5 dakika
FLOSS_TIMEOUT_SECONDS = 300  # 5 dakika
DIE_TIMEOUT_SECONDS = 60
UPX_TIMEOUT_SECONDS = 60
UNPACKED_SUFFIX = ".unpacked"
CLEAN_SUFFIX = ".clean"  # de4dot çıktısı
PYTHON_TOOL_TIMEOUT_SECONDS = 60  # pyinstxtractor, pycdc/decompyle3
DOTNET_TOOL_TIMEOUT_SECONDS = 60  # de4dot
DOTNET_DECOMPILE_TIMEOUT_SECONDS = 120  # ilspycmd (büyük assembly'ler daha uzun sürer)
SHA256_CHUNK_SIZE = 1024 * 1024  # 1 MiB
YARA_RULES_ENV = "CROWBAR_YARA_RULES"  # run_yara'da rules_dir verilmezse kullanılır

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

    floss_iocs = run_floss(state.file_path)  # hata durumunda []
    # Hata/timeout durumunda: ({"error": ...}, [])
    capabilities, ghidra_hints = run_capa(state.file_path)

    imports = extract_imports(state.file_path)  # PE değilse []
    entropy = section_entropy(state.file_path)  # PE değilse {}
    combos = match_import_combos(imports)

    # Mevcut değerlere ekle, tekilleştir
    extracted_strings = _unique([*state.extracted_strings, *floss_iocs])

    new_findings = build_findings(
        yara_results=state.yara_results,
        capabilities=capabilities,
        ghidra_hints=ghidra_hints,
        import_combos=combos,
        entropy=entropy,
        ioc_strings=extracted_strings,
    )

    return {
        "extracted_strings": extracted_strings,
        "capabilities": capabilities,
        "ghidra_hints": ghidra_hints,
        "findings": merge_findings(state.findings, new_findings),
    }


# --------------------------------------------------------------------------- #
# pefile: importlar, section entropy, import kombinasyonları
# --------------------------------------------------------------------------- #
HIGH_ENTROPY_THRESHOLD = 7.0

def extract_imports(file_path: str) -> list[str]:
    """PE import tablosundaki API isimlerini döndürür (tekilleştirilmiş, sıra korunur).

    Geçerli bir PE değilse, pefile kurulu değilse veya dosya okunamazsa ``[]`` döner.
    """
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


def section_entropy(file_path: str) -> dict[str, float]:
    """PE section'larının Shannon entropy değerlerini döndürür: ``{".text": 6.2, ...}``.

    Aynı isimli section'lar ``name#2`` biçiminde ayrıştırılır. Geçerli PE değilse ``{}``.
    """
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


def build_findings(
    *,
    yara_results: list[dict[str, Any]],
    capabilities: dict[str, Any],
    ghidra_hints: list[dict[str, Any]],
    import_combos: list[str],
    entropy: dict[str, float],
    ioc_strings: list[str],
) -> list[Finding]:
    """Araç çıktılarını ``Finding`` listesine çevirir (saf mantık).

    Sıra, bağlam bütçesi daraldığında en değerli kanıtlar önde kalsın diye:
    yara, capa, import combo, entropy, floss.
    """
    findings: list[Finding] = yara_findings(yara_results)

    # capa: adresli eşleşmeler (ghidra_hints) + adresi olmayan kurallar + ATT&CK/MBC
    hints = [h for h in ghidra_hints if isinstance(h, dict) and h.get("rule")]
    hinted_rules = {str(h["rule"]) for h in hints}
    for hint in hints:
        findings.append(
            Finding(source="capa", kind="rule", value=str(hint["rule"]), address=str(hint.get("offset") or ""))
        )
    for rule in capabilities.get("matched_rules", []) or []:
        if str(rule) not in hinted_rules:
            findings.append(Finding(source="capa", kind="rule", value=str(rule)))
    for tech in capabilities.get("mitre_attack", []) or []:
        findings.append(Finding(source="capa", kind="attack", value=str(tech)))
    for behavior in capabilities.get("malware_behavior", []) or []:
        findings.append(Finding(source="capa", kind="behavior", value=str(behavior)))

    for combo in import_combos:
        findings.append(Finding(source="import_combo", kind="behavior", value=combo))

    for name, value in entropy.items():
        if value > HIGH_ENTROPY_THRESHOLD:
            findings.append(Finding(source="pefile_entropy", kind="high_entropy", value=f"{name}: {value:.2f}"))

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

    result = run_ghidra(state.file_path, state.ghidra_hints, state.findings)
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
        db.insert_functions_and_calls(sha256, state.source_code, db_path)
        if state.analysis_report:  # ai_supervisor_agent'ın ürettiği ana rapor
            db.insert_llm_claims(sha256, state.analysis_report, db_path)
    except Exception as exc:  # noqa: BLE001 - kalıcılık hatası analiz sonucunu düşürmemeli
        logger.error("[db_writer_node] veritabanı hatası: %s: %s", type(exc).__name__, exc)
    return {}

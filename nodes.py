"""LangGraph nodes (stubs for now).

Rules:
  * Each node receives ``AgentState`` and returns only the fields to update as a ``dict``.
  * External tool (subprocess/CLI) integration is being added step by step: only capa is
    ready for now; the rest are marked with ``TODO``.
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
except ImportError:  # if not installed, PE helpers return empty results; the flow does not crash
    pefile = None  # type: ignore[assignment]

try:
    import tlsh
except ImportError:  # if not installed (py-tlsh), compute_tlsh returns ""; the flow does not crash
    tlsh = None  # type: ignore[assignment]

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
CLEAN_SUFFIX = ".clean"  # de4dot output
PYTHON_TOOL_TIMEOUT_SECONDS = 60  # pyinstxtractor, pycdc/decompyle3
DOTNET_TOOL_TIMEOUT_SECONDS = 60  # de4dot
DOTNET_DECOMPILE_TIMEOUT_SECONDS = 120  # ilspycmd (large assemblies take longer)
SHA256_CHUNK_SIZE = 1024 * 1024  # 1 MiB
YARA_RULES_ENV = "CROWBAR_YARA_RULES"  # used by run_yara when rules_dir is not given
CAPA_RULES_ENV = "CAPA_RULES"  # rule directory for capa -r; if empty, capa's built-in rules are tried

# YARA rule meta field for treating a rule as "definitely known malware" (e.g. meta: confidence = "known_malware")
KNOWN_MALWARE_META_KEY = "classification"
KNOWN_MALWARE_META_VALUE = "known_malware"


def _env_flag(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in ("1", "true", "yes", "on")


# Tool profile: "deep" (default; runs capa + FLOSS + Ghidra) or "core" (quick scan:
# skips capa, FLOSS and Ghidra). DIE, YARA, pefile/readelf, unpackers and TLSH run in
# both profiles.
TOOL_PROFILE_ENV = "CROWBAR_TOOL_PROFILE"
TOOL_PROFILES = ("core", "deep")
DEFAULT_TOOL_PROFILE = "deep"


def get_tool_profile() -> str:
    """Reads ``CROWBAR_TOOL_PROFILE`` (on every call): ``"core"`` | ``"deep"``.

    Empty means ``deep``. An unrecognized value (typo) falls back to ``deep`` with a
    warning, so analysis is never silently reduced.
    """
    raw = os.getenv(TOOL_PROFILE_ENV, "").strip().lower()
    if not raw:
        return DEFAULT_TOOL_PROFILE
    if raw in TOOL_PROFILES:
        return raw
    logger.warning("[tool_profile] unknown %s=%r; using '%s' (valid: %s)",
                   TOOL_PROFILE_ENV, raw, DEFAULT_TOOL_PROFILE, ", ".join(TOOL_PROFILES))
    return DEFAULT_TOOL_PROFILE


# --------------------------------------------------------------------------- #
# Helper (pure) logic: requires no external tools and is testable.
# --------------------------------------------------------------------------- #
def decide_route(die_info: dict[str, Any], yara_results: list[dict[str, Any]]) -> RouteFlag:
    """Determines ``route_flag`` from DIE and YARA results.

    ``die_info``: output of ``run_die`` (``packer``, ``language``, ``compiler``,
    ``detected``, etc.). An empty dict is valid and yields the ``native`` path.
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
    return "native"  # default: path that checks for packers such as UPX


def compute_sha256(file_path: str) -> str:
    """Computes the file's SHA-256 digest (hex) in a memory-friendly way, reading in chunks.

    If the file cannot be read, the error is logged and an empty string is returned.
    """
    digest = hashlib.sha256()
    try:
        with open(file_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(SHA256_CHUNK_SIZE), b""):
                digest.update(chunk)
    except OSError as exc:
        logger.error("[entry_node] failed to compute sha256: %s", exc)
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
    """Reduces the DIE ``filetype`` value (PE32, PE64, ELF64, ...) to the contract form."""
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
    """Extracts sample/route information from raw ``diec --json`` output (pure logic).

    Return keys: ``file_type``, ``packer``, ``arch`` (if present), ``compiler``,
    ``language`` (if present) and ``detected`` (all detection names, for routing).
    Returns ``{}`` for an unexpected structure. If no packer is detected, ``packer`` = ``"none"``.
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
    """Runs ``diec --json <file_path>``; returns ``file_type``/``arch``/``packer`` (+ compiler).

    If the tool is missing, or on timeout, a non-zero exit code or invalid JSON, it does
    not crash; the error is logged and ``{}`` is returned.
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
            stderr = proc.stderr.strip() or "stderr empty"
            msg = f"diec exited with code {proc.returncode}: {stderr}"
        else:
            report = json.loads(proc.stdout)
            if isinstance(report, dict):
                return _parse_die_report(report)
            msg = "diec returned an unexpected JSON structure (not a dict)"
    except subprocess.TimeoutExpired:
        msg = f"diec did not finish within {DIE_TIMEOUT_SECONDS} seconds (timeout)"
    except FileNotFoundError as exc:
        msg = f"diec or the target file was not found: {exc}"
    except json.JSONDecodeError as exc:
        msg = f"diec output could not be parsed as JSON: {exc}"
    except Exception as exc:  # noqa: BLE001 - the workflow must never crash
        msg = f"unexpected error while running diec: {type(exc).__name__}: {exc}"

    logger.error("[entry_node] %s", msg)
    return {}


# --------------------------------------------------------------------------- #
# YARA
# --------------------------------------------------------------------------- #
def run_yara(file_path: str, rules_dir: str = "") -> list[dict[str, Any]]:
    """Applies YARA rules to the file; returns ``[{"rule", "tags", "meta"}]``.

    Returns ``[]`` if ``yara-python`` is not installed or the rule directory is not
    given/found (stub behavior). If ``rules_dir`` is empty, the ``CROWBAR_YARA_RULES``
    environment variable is used.
    """
    rules_dir = rules_dir or os.environ.get(YARA_RULES_ENV, "")
    if not rules_dir:
        return []

    try:
        import yara  # type: ignore[import-not-found]
    except ImportError:
        logger.warning("[entry_node] yara-python is not installed; YARA scan skipped")
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
    except Exception as exc:  # noqa: BLE001 - the workflow must never crash
        logger.error("[entry_node] YARA error: %s: %s", type(exc).__name__, exc)
        return []


# --------------------------------------------------------------------------- #
# Pre-scan
# --------------------------------------------------------------------------- #
def entry_node(state: AgentState) -> dict[str, Any]:
    """Performs the SHA-256 + DIE + YARA pre-scan; sets ``sample`` and ``route_flag``."""
    logger.info("[entry_node] %s", state.file_path)

    sha256 = compute_sha256(state.file_path)
    die_info = run_die(state.file_path)  # {} if the tool is missing/an error occurs
    yara_results = run_yara(state.file_path)  # [] if no rules/library

    route = decide_route(die_info, yara_results)

    # If DIE gave no information, SampleInfo defaults ("unknown") are kept
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
        # fast_track skips static_feature_node; YARA evidence should still reach findings
        "findings": merge_findings(state.findings, yara_findings(yara_results)),
    }


# --------------------------------------------------------------------------- #
# Unpack nodes
# --------------------------------------------------------------------------- #
def _run_tool(cmd: list[str], timeout: int, cwd: str | None = None) -> subprocess.CompletedProcess[str] | None:
    """Runs an external tool. Returns the result only if ``returncode == 0``; otherwise ``None``.

    If the tool is missing, times out or exits with a non-zero code, the error is logged;
    it never raises.
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
        logger.warning("[unpack] %s did not finish within %d seconds (timeout)", cmd[0], timeout)
        return None
    except FileNotFoundError as exc:
        logger.warning("[unpack] %s not found: %s", cmd[0], exc)
        return None
    except Exception as exc:  # noqa: BLE001 - the workflow must never crash
        logger.warning("[unpack] %s could not be run: %s: %s", cmd[0], type(exc).__name__, exc)
        return None

    if proc.returncode != 0:
        tail = (proc.stderr.strip() or proc.stdout.strip() or "no output")[-300:]
        logger.warning("[unpack] %s exited with code %s: %s", cmd[0], proc.returncode, tail)
        return None
    return proc


def _find_main_pyc(extracted_dir: str, exe_stem: str, extractor_stdout: str) -> str | None:
    """Finds the application's main ``.pyc`` file in the pyinstxtractor output folder.

    Order: (1) one matching the exe name, (2) the one pyinstxtractor reports as the
    "Possible entry point", (3) the largest application .pyc. PyInstaller's own
    ``pyi*`` helper scripts are always excluded.
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
    """Converts a .pyc to Python source with ``pycdc``, falling back to ``decompyle3``; else ``""``."""
    for tool in ("pycdc", "decompyle3"):
        proc = _run_tool([tool, pyc_path], PYTHON_TOOL_TIMEOUT_SECONDS)
        if proc is not None and proc.stdout.strip():
            return proc.stdout
    return ""


def _extract_python_source(file_path: str) -> str:
    """Extracts the main script's Python source from a PyInstaller exe; ``""`` on failure."""
    temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    try:
        abs_path = os.path.abspath(file_path)
        # pyinstxtractor writes its output into the working directory: keep it away from the original file
        proc = _run_tool(["pyinstxtractor", abs_path], PYTHON_TOOL_TIMEOUT_SECONDS, cwd=temp.name)
        if proc is None:
            return ""

        base = os.path.basename(abs_path)
        extracted_dir = os.path.join(temp.name, base + "_extracted")
        if not os.path.isdir(extracted_dir):
            logger.warning("[unpack_python_node] pyinstxtractor output folder not found: %s", extracted_dir)
            return ""

        pyc_path = _find_main_pyc(extracted_dir, os.path.splitext(base)[0], proc.stdout)
        if pyc_path is None:
            logger.warning("[unpack_python_node] main .pyc file not found")
            return ""
        return _decompile_pyc(pyc_path)
    except Exception as exc:  # noqa: BLE001 - the workflow must never crash
        logger.warning("[unpack_python_node] unexpected error: %s: %s", type(exc).__name__, exc)
        return ""
    finally:
        temp.cleanup()


def unpack_python_node(state: AgentState) -> dict[str, Any]:
    """pyinstxtractor + pycdc/decompyle3: extracts Python source from a PyInstaller exe.

    Returns ``{}`` if the route is not ``python``. If any step fails (tool missing,
    timeout, no source produced) it returns ``{"route_flag": "native"}`` so that
    ``deep_inspection_node`` can run Ghidra (native fallback).
    """
    logger.info("[unpack_python_node]")
    if state.sample.route != "python":
        return {}

    code = _extract_python_source(state.file_path)
    if not code.strip():
        logger.warning("[unpack_python_node] could not extract source; native fallback")
        return {"route_flag": "native"}
    func = DecompiledFunction(offset="", name="main_script", priority=10, c_code=code)
    return {"source_code": [func]}


def _extract_dotnet_source(file_path: str) -> str:
    """Cleans with de4dot and produces C# source with ilspycmd; ``""`` on failure."""
    clean_path = file_path + CLEAN_SUFFIX
    try:
        if os.path.exists(clean_path):
            os.remove(clean_path)  # leftover output from a previous run

        if _run_tool(["de4dot", file_path, "-o", clean_path], DOTNET_TOOL_TIMEOUT_SECONDS) is None:
            return ""
        if not os.path.isfile(clean_path):
            logger.warning("[unpack_dotnet_node] de4dot did not produce an output file")
            return ""

        # Note: ``-p`` (project mode) requires ``-o <folder>``; stdout mode emits a single C# file.
        proc = _run_tool(["ilspycmd", clean_path], DOTNET_DECOMPILE_TIMEOUT_SECONDS)
        return proc.stdout if proc is not None and proc.stdout.strip() else ""
    except Exception as exc:  # noqa: BLE001 - the workflow must never crash
        logger.warning("[unpack_dotnet_node] unexpected error: %s: %s", type(exc).__name__, exc)
        return ""
    finally:
        # Do not leave artifacts next to the original sample (not needed since file_path is unchanged)
        try:
            if os.path.exists(clean_path):
                os.remove(clean_path)
        except OSError:
            pass


def unpack_dotnet_node(state: AgentState) -> dict[str, Any]:
    """de4dot (deobfuscation) + ilspycmd (decompile): extracts C# source from a .NET assembly.

    Returns ``{}`` if the route is not ``dotnet``. If any step fails (tool missing,
    timeout, no source produced) it returns ``{"route_flag": "native"}`` so that
    ``deep_inspection_node`` can run Ghidra (native fallback).
    """
    logger.info("[unpack_dotnet_node]")
    if state.sample.route != "dotnet":
        return {}

    code = _extract_dotnet_source(state.file_path)
    if not code.strip():
        logger.warning("[unpack_dotnet_node] could not extract source; native fallback")
        return {"route_flag": "native"}
    func = DecompiledFunction(offset="", name="dotnet_source", priority=10, c_code=code)
    return {"source_code": [func]}


def unpack_native_node(state: AgentState) -> dict[str, Any]:
    """Unpacks UPX-packed samples; updates ``file_path`` for subsequent nodes.

    Does nothing (``{}``) if the packer is not UPX. If unpacking fails (tool missing,
    timeout, corrupt header) it does not crash; the original file is used.
    ``sample.sha256`` keeps the identity of the original file (this node does not touch it).
    """
    logger.info("[unpack_native_node]")

    if "upx" not in state.sample.packer.lower():
        return {}

    unpacked_path = state.file_path + UNPACKED_SUFFIX
    if _run_upx_unpack(state.file_path, unpacked_path):
        logger.info("[unpack_native_node] UPX unpacked: %s", unpacked_path)
        return {"file_path": unpacked_path}
    return {}


def _run_upx_unpack(src: str, dst: str) -> bool:
    """Runs ``upx -d -o <dst> <src>``; returns ``True`` on success. Never raises on error."""
    try:
        # UPX refuses to overwrite an existing output file; clean up leftovers from a previous run
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
        stderr = (proc.stderr.strip() or proc.stdout.strip() or "no output")[-300:]
        msg = f"upx exited with code {proc.returncode} (or the output file is missing): {stderr}"
    except subprocess.TimeoutExpired:
        msg = f"upx did not finish within {UPX_TIMEOUT_SECONDS} seconds (timeout)"
    except FileNotFoundError as exc:
        msg = f"upx not found: {exc}"
    except Exception as exc:  # noqa: BLE001 - the workflow must never crash
        msg = f"unexpected error while running upx: {type(exc).__name__}: {exc}"

    logger.warning("[unpack_native_node] %s; continuing with the original file", msg)
    # Do not leave a partial output behind
    try:
        if os.path.exists(dst):
            os.remove(dst)
    except OSError:
        pass
    return False


# --------------------------------------------------------------------------- #
# Static analysis
# --------------------------------------------------------------------------- #
def static_feature_node(state: AgentState) -> dict[str, Any]:
    """FLOSS + capa + pefile (imports/entropy); collects all findings under ``findings``."""
    profile = get_tool_profile()
    logger.info("[static_feature_node] profile=%s", profile)

    if profile == "core":
        # Quick scan: heavy tools (FLOSS, capa) are not run at all; treat as empty results.
        floss_iocs, floss_hints = [], []
        capabilities, ghidra_hints = {}, []
    else:
        floss_iocs, floss_hints = run_floss_with_hints(state.file_path)  # on error: ([], [])
        # On error/timeout: ({"error": ...}, [])
        capabilities, ghidra_hints = run_capa(state.file_path)
        capabilities, ghidra_hints = _filter_trivial_capa(capabilities, ghidra_hints)

    # The raw import list does NOT go into findings (noise); it is used only for combo matching and imphash.
    imports = extract_imports(state.file_path)  # PE: pefile, ELF: readelf; otherwise []
    imphash = compute_imphash(state.file_path, imports)  # PE: pefile imphash, ELF: MD5(imports); else ""
    tlsh_hash = compute_tlsh(state.file_path)  # library missing / file < 50 bytes -> ""
    entropy = section_entropy(state.file_path)  # PE: pefile, ELF: readelf -S; otherwise {}
    entropy_source = "elf_entropy" if is_elf(state.file_path) else "pefile_entropy"
    combos = match_import_combos(imports)

    # PE metadata: the file is loaded once, and the same object is given to all three helpers
    pe = _load_pe(state.file_path)
    pe_metadata: list[Finding] = []
    try:
        pe_metadata = pe_metadata_findings(pe)
    except Exception as exc:  # noqa: BLE001 - a metadata error must not bring down the rest of the analysis
        logger.warning("[static_feature_node] could not read PE metadata: %s: %s", type(exc).__name__, exc)
    finally:
        if pe is not None:
            pe.close()

    # Add to existing values, deduplicate
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
        tlsh_hash=tlsh_hash,
    )

    return {
        "extracted_strings": extracted_strings,
        "capabilities": capabilities,
        "ghidra_hints": ghidra_hints,
        "floss_hints": floss_hints,
        # identity + existence check: FLOSS decoded/stack/tight values (floss_hints) are excluded
        "findings": finalize_findings(
            merge_findings(state.findings, new_findings),
            state.file_path,
            {h["value"] for h in floss_hints if isinstance(h, dict) and isinstance(h.get("value"), str)},
        ),
    }


# --------------------------------------------------------------------------- #
# pefile: imports, section entropy, import combinations
# --------------------------------------------------------------------------- #
HIGH_ENTROPY_THRESHOLD = 7.0
ELF_MAGIC = b"\x7fELF"
READELF_TIMEOUT_SECONDS = int(os.environ.get("CROWBAR_READELF_TIMEOUT", "30"))

# `readelf --wide --dyn-syms` line:
#   "    12: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND ptrace@GLIBC_2.2.5 (2)"
# Groups: (Type, Name). Entries with Ndx = UND are symbols imported from outside (libc/ld.so).
_READELF_UND_RE = re.compile(
    r"^\s*\d+:\s+[0-9A-Fa-f]+\s+\d+\s+(?P<type>\w+)\s+\w+\s+\w+\s+UND\s+(?P<name>\S+)"
)
# Data symbols (stdout, environ...) and NOTYPE weak symbols (__gmon_start__) are not function imports.
_ELF_IMPORT_TYPES = frozenset({"FUNC", "IFUNC", "GNU_IFUNC"})


def is_elf(file_path: str) -> bool:
    """Are the file's first 4 bytes ``\\x7fELF``? ``False`` if it cannot be read."""
    try:
        with open(file_path, "rb") as fh:
            return fh.read(len(ELF_MAGIC)) == ELF_MAGIC
    except OSError:
        return False


def parse_readelf_dynsyms(output: str) -> list[str]:
    """Extracts UND function names from ``readelf --wide --dyn-syms`` output (pure logic).

    Version suffixes (``@GLIBC_2.2.5``) are stripped; results are deduplicated, order preserved.
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
    """Returns imported function names (UND) from the ELF dynamic symbol table.

    If ``readelf`` is missing, times out, exits non-zero or another error occurs,
    the error is logged and ``[]`` is returned. Statically linked ELF files have no
    dynamic symbol table, so ``[]`` is returned.
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
            env={**os.environ, "LC_ALL": "C"},  # make the column format locale-independent
        )
    except FileNotFoundError:
        logger.warning("[static_feature_node] readelf not found; skipping ELF imports")
        return []
    except subprocess.TimeoutExpired:
        logger.warning("[static_feature_node] readelf did not finish within %d seconds (timeout)", READELF_TIMEOUT_SECONDS)
        return []
    except Exception as exc:  # noqa: BLE001 - the workflow must never crash
        logger.warning("[static_feature_node] readelf could not be run: %s: %s", type(exc).__name__, exc)
        return []

    if proc.returncode != 0:
        logger.warning(
            "[static_feature_node] readelf exited with code %d: %s", proc.returncode, (proc.stderr or "").strip()[:200]
        )
        return []
    return parse_readelf_dynsyms(proc.stdout or "")


def extract_imports(file_path: str) -> list[str]:
    """Returns the API/function names imported by the file (deduplicated, order preserved).

    * If the first 4 bytes are ``\\x7fELF``, UND symbols via ``readelf --wide --dyn-syms`` (``extract_elf_imports``).
    * Otherwise the PE import table via pefile.

    Returns ``[]`` if it is not a valid PE/ELF, the tool is missing or the file cannot be read.
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
                if imp.name:  # ordinal-only imports are skipped
                    names.append(imp.name.decode("utf-8", errors="replace"))
        return _unique(names)
    except pefile.PEFormatError:
        return []
    except Exception as exc:  # noqa: BLE001 - the workflow must never crash
        logger.warning("[static_feature_node] could not read imports: %s: %s", type(exc).__name__, exc)
        return []
    finally:
        if pe is not None:
            pe.close()


PE_MAGIC = b"MZ"
ENTROPY_READ_CHUNK = 1024 * 1024  # 1 MiB

# `readelf -S -W` section line:
#   "  [ 1] .interp           PROGBITS        00000000004002a8 0002a8 00001c 00   A  0   0  1"
# Groups: Nr, Name, Type, (Address), Off, Size  (Off/Size hex)
_READELF_SECTION_RE = re.compile(
    r"^\s*\[\s*(?P<nr>\d+)\]\s+(?P<name>\S+)\s+(?P<type>\S+)\s+[0-9A-Fa-f]+\s+"
    r"(?P<off>[0-9A-Fa-f]+)\s+(?P<size>[0-9A-Fa-f]+)\s"
)


def is_pe(file_path: str) -> bool:
    """Are the file's first 2 bytes ``MZ``? ``False`` if it cannot be read."""
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
    """Shannon entropy of the byte array (0.0 - 8.0). 0.0 for empty data."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte, n in Counter(data).items():
        counts[byte] = n
    return _entropy_from_counts(counts, len(data))


def file_range_entropy(file_path: str, offset: int, size: int) -> float | None:
    """Reads ``size`` bytes from ``offset`` in the file and computes Shannon entropy.

    It is read in chunks to avoid bloating memory for large sections. Returns ``None``
    if no bytes can be read (offset outside the file, ``size`` 0) or the file cannot be read.
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
    """Extracts a ``(name, file_offset, size)`` list from ``readelf -S -W`` output (pure logic).

    Offset/size are converted from hex to integers. Sections that take no space in the file
    (``NULL``, ``NOBITS``/.bss, Nr=0) and those with size 0 are skipped.
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
    """Entropy values of ELF sections (``readelf -S -W`` + reading bytes from the file). Error -> ``{}``."""
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
        logger.warning("[static_feature_node] readelf not found; skipping ELF entropy")
        return {}
    except subprocess.TimeoutExpired:
        logger.warning("[static_feature_node] readelf -S did not finish within %d seconds (timeout)", READELF_TIMEOUT_SECONDS)
        return {}
    except Exception as exc:  # noqa: BLE001 - the workflow must never crash
        logger.warning("[static_feature_node] readelf -S could not be run: %s: %s", type(exc).__name__, exc)
        return {}
    if proc.returncode != 0:
        logger.warning("[static_feature_node] readelf -S exited with code %d", proc.returncode)
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
    """Import digest (family grouping key).

    * PE (``MZ``): ``pefile`` ``get_imphash()``; error/no pefile -> ``""``.
    * ELF (``\\x7fELF``): ``md5(",".join(sorted(imports)))`` (``""`` if the import list is empty). Sorting
      ensures the same import set yields the same digest across different linker/compiler orderings.
    * Other files -> ``""``.
    """
    if is_elf(file_path):
        names = sorted(n for n in imports if isinstance(n, str) and n)
        if not names:
            return ""
        return hashlib.md5(",".join(names).encode()).hexdigest()  # noqa: S324 - not for security, a grouping key
    if is_pe(file_path):
        if pefile is None:
            return ""
        pe = None
        try:
            pe = pefile.PE(file_path, fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
            return pe.get_imphash() or ""
        except Exception as exc:  # noqa: BLE001 - the workflow must never crash
            logger.warning("[static_feature_node] could not compute imphash: %s: %s", type(exc).__name__, exc)
            return ""
        finally:
            if pe is not None:
                pe.close()
    return ""


TLSH_MIN_BYTES = 50  # TLSH lower bound: shorter input cannot produce a hash
TLSH_MAX_FILE_BYTES = 256 * 1024 * 1024  # read entirely into memory; larger files are skipped


def compute_tlsh(file_path: str) -> str:
    """The file's TLSH (fuzzy) hash; used to group similar samples.

    Returns ``""`` if ``py-tlsh`` is not installed, the file cannot be read, the file is
    smaller than ``TLSH_MIN_BYTES`` (50) bytes (or larger than ``TLSH_MAX_FILE_BYTES``),
    or TLSH finds insufficient variance (``TNULL``/empty). Never raises an exception.
    """
    if tlsh is None:
        return ""
    try:
        size = os.path.getsize(file_path)
        if size < TLSH_MIN_BYTES or size > TLSH_MAX_FILE_BYTES:
            return ""
        with open(file_path, "rb") as fh:
            data = fh.read()
        if len(data) < TLSH_MIN_BYTES:
            return ""
        digest = tlsh.hash(data)
    except Exception as exc:  # noqa: BLE001 - a hash error must not bring down the analysis
        logger.warning("[static_feature_node] could not compute tlsh: %s: %s", type(exc).__name__, exc)
        return ""
    if isinstance(digest, bytes):
        digest = digest.decode("ascii", "ignore")
    digest = str(digest or "").strip()
    return "" if digest.upper() == "TNULL" else digest


def section_entropy(file_path: str) -> dict[str, float]:
    """Returns the Shannon entropy values of sections: ``{".text": 6.2, ...}``.

    * ELF (``\\x7fELF``): section offset/size via ``readelf -S -W``, computed over bytes read from the file.
    * Otherwise PE sections via pefile.

    Sections with the same name are disambiguated as ``name#2``. ``{}`` if not a valid PE/ELF.
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
    except Exception as exc:  # noqa: BLE001 - the workflow must never crash
        logger.warning("[static_feature_node] could not compute entropy: %s: %s", type(exc).__name__, exc)
        return {}
    finally:
        if pe is not None:
            pe.close()


# --------------------------------------------------------------------------- #
# PE metadata: Authenticode presence, version info, manifest privilege level
# --------------------------------------------------------------------------- #
RT_MANIFEST = 24
_DEFAULT_SECURITY_DIRECTORY_INDEX = 4  # IMAGE_DIRECTORY_ENTRY_SECURITY
# Output order is determined by this list
PE_VERSION_KEYS = (
    "OriginalFilename",
    "CompanyName",
    "FileDescription",
    "LegalCopyright",
    "ProductName",
    "FileVersion",
)
PE_VERSION_VALUE_MAX = 200  # sample-derived value: keep it from bloating the context
# The only three values Windows accepts; any other sample-derived text is not added as a finding.
_EXECUTION_LEVELS = {
    "asinvoker": "asInvoker",
    "highestavailable": "highestAvailable",
    "requireadministrator": "requireAdministrator",
}
_EXECUTION_LEVEL_RE = re.compile(
    r"<(?:\w+:)?requestedExecutionLevel\b[^>]*?\blevel\s*=\s*[\"']([^\"']*)[\"']", re.IGNORECASE
)


def _load_pe(file_path: str) -> Any | None:
    """Loads the file ONCE with pefile (import + resource directories parsed).

    ``None`` for ELF, an invalid PE (``PEFormatError``), an unreadable file or when
    ``pefile`` is missing. The caller must close the returned object (``pe.close()``).
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
    except Exception as exc:  # noqa: BLE001 - including PEFormatError; the workflow must never crash
        if pe is not None:
            pe.close()
        if type(exc).__name__ != "PEFormatError":  # a non-PE file is expected; fail silently
            logger.warning("[static_feature_node] could not load PE: %s: %s", type(exc).__name__, exc)
        return None


def check_authenticode(pe: Any) -> bool:
    """``True`` if the security (certificate) data directory's ``VirtualAddress`` is greater than 0.

    This only reports the **presence** of a signature; its validity is not verified. ``False`` on error.
    """
    try:
        index = pefile.DIRECTORY_ENTRY.get("IMAGE_DIRECTORY_ENTRY_SECURITY", _DEFAULT_SECURITY_DIRECTORY_INDEX)
        directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        return index < len(directories) and directories[index].VirtualAddress > 0
    except Exception as exc:  # noqa: BLE001
        logger.debug("[static_feature_node] could not read authenticode: %s: %s", type(exc).__name__, exc)
        return False


def _to_text(value: Any) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return str(value).replace("\x00", "").strip()


def extract_pe_version_info(pe: Any) -> list[str]:
    """Returns ``StringFileInfo`` values as ``["OriginalFilename: calc.exe", ...]``.

    Only fields in ``PE_VERSION_KEYS`` are taken (fixed order), empty values are skipped, and each
    value is limited to ``PE_VERSION_VALUE_MAX`` characters. ``[]`` if there is no version info or an error occurs.
    """
    try:
        values: dict[str, str] = {}
        for info in getattr(pe, "FileInfo", None) or []:
            # Newer pefile: FileInfo = [[entry, ...], ...]; older versions may return a flat list
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
        logger.debug("[static_feature_node] could not read version info: %s: %s", type(exc).__name__, exc)
        return []


def _decode_manifest(raw: bytes) -> str:
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")


def parse_execution_level(manifest_xml: str) -> str:
    """Extracts the ``requestedExecutionLevel level="..."`` value from manifest XML.

    Only values Windows recognizes (asInvoker, highestAvailable, requireAdministrator) are returned;
    ``""`` if there is no other text or match.
    """
    match = _EXECUTION_LEVEL_RE.search(manifest_xml or "")
    return _EXECUTION_LEVELS.get(match.group(1).strip().lower(), "") if match else ""


def extract_pe_manifest(pe: Any) -> str:
    """Returns the ``requestedExecutionLevel`` value from the RT_MANIFEST (type 24) resource.

    ``""`` if there is no resource directory, manifest or level, or an error occurs.
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
        logger.debug("[static_feature_node] could not read manifest: %s: %s", type(exc).__name__, exc)
        return ""


def pe_metadata_findings(pe: Any) -> list[Finding]:
    """Produces ``pe_metadata`` findings from the loaded ``pe`` object (without re-reading I/O)."""
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
    """Returns suspicious import combinations (case-insensitive).

    E.g. VirtualAlloc + WriteProcessMemory + CreateRemoteThread -> ``["Process Injection Combo"]``.
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
    """Determines the type of a FLOSS IoC string: url | ip | registry | file."""
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
    tlsh_hash: str = "",
) -> list[Finding]:
    """Converts tool outputs into a ``Finding`` list (pure logic).

    The order keeps the most valuable evidence first when the context budget shrinks:
    yara, capa, import combo, imphash, tlsh, entropy, floss.
    The raw import list intentionally produces no findings; only the matched combos and ``imphash`` are included.
    ``entropy_source``: ``pefile_entropy`` for PE, ``elf_entropy`` for ELF.
    """
    findings: list[Finding] = yara_findings(yara_results)

    # capa: matches with addresses (ghidra_hints) + rules without an address + ATT&CK/MBC
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

    if tlsh_hash:  # fuzzy hash: for grouping similar samples (not decision evidence)
        findings.append(Finding(source="tlsh", kind="grouping_key", value=tlsh_hash))

    findings.extend(pe_metadata or [])

    for name, value in entropy.items():
        if value > HIGH_ENTROPY_THRESHOLD:
            findings.append(Finding(source=entropy_source, kind="high_entropy", value=f"{name}: {value:.2f}"))

    for text in ioc_strings:
        if isinstance(text, str) and text.strip():
            findings.append(Finding(source="floss", kind=_ioc_kind(text), value=text))

    return findings


# --------------------------------------------------------------------------- #
# Finding integrity: identity + "does it really exist in the binary?" check
# --------------------------------------------------------------------------- #
# IoC types that can be searched in raw bytes because they are extracted as text from the file.
VERIFIABLE_IOC_KINDS = frozenset({"ip", "url", "domain", "email"})
VERIFIABLE_SOURCES = frozenset({"floss"})
MAX_VERIFY_VALUES = 500  # upper bound on unique values (each is searched in the whole file); extras are not checked


def compute_finding_id(f: Finding) -> str:
    """Deterministic finding ID: ``md5(source_kind_value_address)[:8]``."""
    raw = f"{f.source}_{f.kind}_{f.value}_{f.address}"
    return hashlib.md5(raw.encode("utf-8", "replace")).hexdigest()[:8]  # noqa: S324 - identity, not security


def _verifiable(f: Finding, dynamic_values: frozenset[str]) -> bool:
    """Is this a statically extracted, searchable text IoC? (excludes FLOSS decoded/stack/tight)."""
    return (
        (f.source or "").lower() in VERIFIABLE_SOURCES
        and (f.kind or "").lower() in VERIFIABLE_IOC_KINDS
        and bool(f.value)
        and f.value not in dynamic_values
    )


def string_in_file(path: str, values: list[str]) -> dict[str, bool] | None:
    """Does each ``value`` occur in the file's raw bytes (UTF-8 or UTF-16LE)?

    The file is mapped once with ``mmap`` (not loaded into memory). Returns ``None`` if the file
    cannot be read (could not be checked); in that case no finding is marked ``verified=False``.
    """
    import mmap

    result: dict[str, bool] = {}
    try:
        with open(path, "rb") as fh:
            try:
                data = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
            except ValueError:  # an empty file cannot be mmap'ed
                data = b""
            try:
                for value in values:
                    needles = (value.encode("utf-8", "replace"), value.encode("utf-16le", "replace"))
                    result[value] = any(n and data.find(n) != -1 for n in needles)
            finally:
                if not isinstance(data, bytes):
                    data.close()
    except OSError as exc:
        logger.warning("[static_feature_node] could not read the file for finding verification: %s", exc)
        return None
    return result


def finalize_findings(
    findings: list[Finding],
    file_path: str,
    dynamic_values: frozenset[str] | set[str] = frozenset(),
) -> list[Finding]:
    """Assigns ``finding_id`` to every finding and verifies static text IoCs against the file bytes.

    * ``finding_id``: ``compute_finding_id`` (every finding).
    * ``verified=False``: when FLOSS's **static** ip/url/domain/email string does not occur
      anywhere in the file as UTF-8 or UTF-16LE. FLOSS decoded/stack/tight strings
      (``dynamic_values``; generated at runtime, so they are not plaintext in the file) and all
      other types cannot be checked: their ``verified`` value is unchanged (stays ``True``).
      A finding already ``False`` is never turned back into ``True``.
    """
    dynamic = frozenset(dynamic_values)
    targets: list[str] = []
    for f in findings:
        if f.verified and _verifiable(f, dynamic) and f.value not in targets:
            targets.append(f.value)
    if len(targets) > MAX_VERIFY_VALUES:
        logger.warning("[static_feature_node] %d IoC values to verify; checking the first %d",
                       len(targets), MAX_VERIFY_VALUES)
        targets = targets[:MAX_VERIFY_VALUES]
    found = string_in_file(file_path, targets) if targets else {}

    out: list[Finding] = []
    for f in findings:
        update: dict[str, Any] = {"finding_id": compute_finding_id(f)}
        if found and f.value in found and not found[f.value]:
            update["verified"] = False
        out.append(f.model_copy(update=update))
    return out


def merge_findings(existing: list[Finding], new: list[Finding]) -> list[Finding]:
    """Adds new findings to existing ones; deduplicates by (source, kind, value, address)."""
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
# Strict IoC filter: a text is dropped unless it matches at least one of these patterns.
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
    """Keeps texts containing an IP, URL, file extension or registry path (deduplicated)."""
    kept = [
        s
        for s in strings_list
        if isinstance(s, str) and s.strip() and any(p.search(s) for p in _IOC_PATTERNS)
    ]
    return _unique(kept)


def _collect_floss_strings(report: dict[str, Any]) -> list[str]:
    """Collects decoded, stack, tight and static string texts from FLOSS JSON.

    Since ``run_floss`` filters the output with ``filter_iocs``, static string noise does
    not come through; plaintext C2 URLs only become findings this way.
    Entries may be either ``{"string": "..."}`` objects or plain strings.
    """
    strings_section = report.get("strings")
    if not isinstance(strings_section, dict):
        strings_section = report  # on some versions the keys may be at the root level

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
    """Collects function/address metadata for decoded/tight/stack strings.

    Any of the ``function`` (tight/stack), ``decoded_at`` (decoded), ``program_counter`` and
    ``address`` fields that is present is stored. Only values that pass the IoC filter are
    returned, so noise does not increase.
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
    """Runs ``floss -j``; returns (filtered IoCs, decoded-string hints).

    Returns ``([], [])`` on error; the flow does not crash.
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
            stderr = proc.stderr.strip() or "stderr empty"
            msg = f"floss exited with code {proc.returncode}: {stderr}"
        else:
            report = json.loads(proc.stdout)
            if not isinstance(report, dict):
                msg = "floss returned an unexpected JSON structure (not a dict)"
            else:
                iocs = filter_iocs(_collect_floss_strings(report))
                hints = _filter_hints_by_iocs(_collect_floss_hints(report), iocs)
                return iocs, hints
    except subprocess.TimeoutExpired:
        msg = f"floss did not finish within {FLOSS_TIMEOUT_SECONDS} seconds (timeout)"
    except FileNotFoundError as exc:
        msg = f"floss or the target file was not found: {exc}"
    except json.JSONDecodeError as exc:
        msg = f"floss output could not be parsed as JSON: {exc}"
    except Exception as exc:  # noqa: BLE001 - the workflow must never crash
        msg = f"unexpected error while running floss: {type(exc).__name__}: {exc}"

    logger.error("[static_feature_node] %s", msg)
    return [], []


def run_floss(file_path: str) -> list[str]:
    """Backward-compatible wrapper: only the filtered IoC strings."""
    return run_floss_with_hints(file_path)[0]


def _unique(items: list[str]) -> list[str]:
    """Deduplicates while preserving order."""
    return list(dict.fromkeys(items))


def _format_capa_entry(entry: Any, kind: str) -> str | None:
    """Converts a capa ``meta.attack`` / ``meta.mbc`` entry into a readable single line.

    ATT&CK: "T1055.012 - Process Injection::Process Hollowing (Defense Evasion)"
    MBC:    "B0001.025 - Debugger Detection::Software Breakpoints (Anti-Behavioral Analysis)"

    Plain string entries from older capa versions are accepted as-is.
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
        # Structure differs from what was expected: fall back to the "parsed" list.
        parsed = entry.get("parsed")
        if isinstance(parsed, list) and parsed:
            return " :: ".join(str(p) for p in parsed)
        return None

    label = f"{ident} - {name}" if ident and name else (ident or name)
    return f"{label} ({group})" if group else label


def summarize_capa(report: dict[str, Any]) -> dict[str, list[str]]:
    """Reduces raw capa JSON to a small summary suitable for the LLM context.

    It takes only rule names, MITRE ATT&CK and MBC entries; large fields such as
    ``matches`` (logic/match trees) are discarded. It does not raise on unexpected
    structures and skips the relevant part.
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
    """Converts capa address representations (different versions) into a single int virtual address.

    Supported forms:
      * ``{"type": "absolute", "value": 4198400}`` (capa >= 5/7)
      * ``["absolute", 4198400]`` (intermediate versions)
      * ``4198400`` / ``"4198400"`` / ``"0x401000"`` (older versions)

    Returns ``None`` for entries that have no specific memory address (``file``,
    ``no address``, ``relative``, ``token``, etc. types).
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
    """Collects addresses from a capa rule's ``matches`` / ``locations`` structure."""
    addresses: list[int] = []

    def add(raw: Any) -> None:
        addr = _parse_capa_address(raw)
        if addr is not None:
            addresses.append(addr)

    matches = rule.get("matches")
    if isinstance(matches, dict):
        # Older versions: {"<address>": {...match tree...}}
        for key in matches:
            add(key)
    elif isinstance(matches, list):
        # Newer versions: [[<address>, {...match tree...}], ...]
        for item in matches:
            if isinstance(item, (list, tuple)) and item:
                add(item[0])

    locations = rule.get("locations")
    if isinstance(locations, list):
        for loc in locations:
            add(loc)

    return addresses


def _is_file_scope(meta: dict[str, Any]) -> bool:
    """Does the rule match at file level (global)?"""
    scope = meta.get("scope")
    if scope is None:
        scopes = meta.get("scopes")
        scope = scopes.get("static") if isinstance(scopes, dict) else None
    return isinstance(scope, str) and scope.strip().lower() == "file"


def extract_ghidra_hints(report: dict[str, Any]) -> list[dict[str, str]]:
    """Extracts target addresses to pass to Ghidra from raw capa JSON.

    Returns: ``[{"offset": "0x401000", "rule": "encrypt data using AES"}, ...]``
    ``(offset, rule)`` pairs are deduplicated. Rules that match at file level (global)
    or have no specific memory address are skipped. It does not raise on unexpected
    structures and skips the relevant part.
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
    """Runs ``capa -j <file_path>``; returns the ``(summary, ghidra_hints)`` pair.

    On success:
      * summary: ``{"matched_rules": [...], "mitre_attack": [...], "malware_behavior": [...]}``
      * ghidra_hints: ``[{"offset": "0x401000", "rule": "..."}, ...]``
    On error (timeout, capa/file not found, non-zero exit code, invalid JSON) the
    application does not crash; ``({"error": "<message>"}, [])`` is returned.
    """
    try:
        # capa 10 has no embedded rules; the rule directory is given via env (otherwise capa returns its own error)
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
            stderr = proc.stderr.strip() or "stderr empty"
            return {"error": f"capa exited with code {proc.returncode}: {stderr}"}, []

        result = json.loads(proc.stdout)
        if not isinstance(result, dict):
            return {"error": "capa returned an unexpected JSON structure (not a dict)"}, []
        return summarize_capa(result), extract_ghidra_hints(result)

    except subprocess.TimeoutExpired:
        msg = f"capa did not finish within {CAPA_TIMEOUT_SECONDS} seconds (timeout)"
    except FileNotFoundError as exc:
        msg = f"capa or the target file was not found: {exc}"
    except json.JSONDecodeError as exc:
        msg = f"capa output could not be parsed as JSON: {exc}"
    except Exception as exc:  # noqa: BLE001 - the workflow must never crash
        msg = f"unexpected error while running capa: {type(exc).__name__}: {exc}"

    logger.error("[static_feature_node] %s", msg)
    return {"error": msg}, []


def deep_inspection_node(state: AgentState) -> dict[str, Any]:
    """Deep inspection / decompile with Ghidra (headless).

    capa hints and ``state.findings`` (import combos etc.) are passed to Ghidra for
    priority scoring. On error/timeout ``run_ghidra`` returns ``[]``.

    Ghidra guard: if the unpack nodes already produced source code
    (``source_code`` is non-empty) or the route is not ``native``, Ghidra is not run,
    so Python/C# source is not overwritten by decompile output.
    """
    logger.info("[deep_inspection_node]")
    if get_tool_profile() == "core":
        logger.info("[deep_inspection_node] skipped (%s=core: Ghidra is not run)", TOOL_PROFILE_ENV)
        return {}
    if state.source_code or state.route_flag != "native":
        logger.info(
            "[deep_inspection_node] skipped (source_code=%d, route_flag=%s)",
            len(state.source_code),
            state.route_flag,
        )
        return {}

    result = run_ghidra(state.file_path, state.ghidra_hints, state.findings,
                        decoded_hints=list(getattr(state, "floss_hints", []) or []))
    return {"source_code": result}


# --------------------------------------------------------------------------- #
# AI agents (Ollama)
# --------------------------------------------------------------------------- #
def ai_extractor_agent(state: AgentState) -> dict[str, Any]:
    """Cleans FLOSS strings and extracts IoCs (IP, URL, domain, ...)."""
    logger.info("[ai_extractor_agent]")
    # IoC extraction is deterministic (filter_iocs); it is not left to the LLM.
    iocs = dict(state.iocs)
    iocs.setdefault("ioc", _unique([s for s in state.extracted_strings if filter_iocs([s])]))
    return {"iocs": iocs}


def ai_reverser_agent(state: AgentState) -> dict[str, Any]:
    """Reads decompiled code and determines intent (LLM layer).

    With ``CROWBAR_SKIP_LLM=1`` (or ``main.py --no-llm``) no LLM client is
    created; an offline VM produces deterministic state.
    """
    logger.info("[ai_reverser_agent]")
    if _env_flag("CROWBAR_SKIP_LLM"):
        logger.info("[ai_reverser_agent] skipped (CROWBAR_SKIP_LLM=1)")
        return {}
    from llm_layer.nodes import run_reverser
    return run_reverser(state)


def ai_supervisor_agent(state: AgentState) -> dict[str, Any]:
    """Combines all data and produces the final JSON/Markdown report."""
    logger.info("[ai_supervisor_agent]")
    from llm_layer.nodes import run_supervisor
    return run_supervisor(state)


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #
def db_writer_node(state: AgentState) -> dict[str, Any]:
    """Writes analysis results to SQLite (samples, findings, functions, calls, llm_claims).

    If ``sample.sha256`` is empty (file could not be read), nothing is written. Database
    errors do not crash the flow; they are logged. State is not modified (``{}``).
    """
    logger.info("[db_writer_node]")
    if _env_flag("CROWBAR_SKIP_DB"):
        logger.info("[db_writer_node] skipped (CROWBAR_SKIP_DB=1)")
        return {}
    sha256 = state.sample.sha256
    if not sha256:
        logger.warning("[db_writer_node] sha256 is empty; not written to the database")
        return {}

    try:
        # init_db -> sample -> findings -> functions/calls (including llm_summary)
        # -> llm_claims (report and/or verdict); shared with split mode (host_analyze --db).
        db.save_analysis(state)
    except Exception as exc:  # noqa: BLE001 - a persistence error must not bring down the analysis result
        logger.error("[db_writer_node] database error: %s: %s", type(exc).__name__, exc)
    return {}

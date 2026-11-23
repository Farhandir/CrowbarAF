"""LangGraph node functions and backward-compatible re-exports.

This module holds the LangGraph nodes (entry, unpack, static feature, deep inspection,
deterministic IoC extraction, LLM layer nodes, DB writer) and the routing helper.
Tool runners and parsers live in the ``analyzers`` package: ``common`` (small helpers), ``binary`` (PE/ELF static features),
``capa_floss`` (capa/FLOSS), ``triage`` (SHA-256/DIE/YARA), ``unpack`` (Python/.NET/UPX)
and ``findings`` (finding construction and verification). Names are re-exported here for
backward compatibility.
"""

from __future__ import annotations

import logging
import os
import subprocess
from typing import Any

import db
from analyzers.binary import (
    ELF_MAGIC,
    ENTROPY_READ_CHUNK,
    HIGH_ENTROPY_THRESHOLD,
    PE_MAGIC,
    PE_VERSION_KEYS,
    PE_VERSION_VALUE_MAX,
    READELF_TIMEOUT_SECONDS,
    RT_MANIFEST,
    TLSH_MAX_FILE_BYTES,
    TLSH_MIN_BYTES,
    _DEFAULT_SECURITY_DIRECTORY_INDEX,
    _ELF_IMPORT_TYPES,
    _EXECUTION_LEVEL_RE,
    _EXECUTION_LEVELS,
    _READELF_SECTION_RE,
    _READELF_UND_RE,
    _decode_manifest,
    _elf_section_entropy,
    _entropy_from_counts,
    _load_pe,
    _to_text,
    check_authenticode,
    compute_imphash,
    compute_tlsh,
    extract_elf_imports,
    extract_imports,
    extract_pe_manifest,
    extract_pe_version_info,
    file_range_entropy,
    is_elf,
    is_pe,
    match_import_combos,
    parse_execution_level,
    parse_readelf_dynsyms,
    parse_readelf_sections,
    pe_metadata_findings,
    pefile,
    section_entropy,
    shannon_entropy,
    tlsh,
)
from analyzers.capa_floss import (
    CAPA_RULES_ENV,
    CAPA_TIMEOUT_SECONDS,
    FLOSS_TIMEOUT_SECONDS,
    TRIVIAL_CAPA_RULES,
    _FILE_EXT_RE,
    _IOC_PATTERNS,
    _IPV4_RE,
    _REGISTRY_RE,
    _URL_RE,
    _capa_is_trivial,
    _collect_floss_hints,
    _collect_floss_strings,
    _filter_hints_by_iocs,
    _filter_trivial_capa,
    _format_capa_entry,
    _ioc_kind,
    _is_file_scope,
    _parse_capa_address,
    _rule_match_addresses,
    extract_ghidra_hints,
    filter_iocs,
    run_capa,
    run_floss,
    run_floss_with_hints,
    summarize_capa,
)
from analyzers.common import _unique
from analyzers.findings import (
    MAX_VERIFY_VALUES,
    VERIFIABLE_IOC_KINDS,
    VERIFIABLE_SOURCES,
    _verifiable,
    build_findings,
    compute_finding_id,
    finalize_findings,
    merge_findings,
    string_in_file,
    yara_findings,
)
from analyzers.triage import (
    DIE_TIMEOUT_SECONDS,
    KNOWN_MALWARE_META_KEY,
    KNOWN_MALWARE_META_VALUE,
    SHA256_CHUNK_SIZE,
    YARA_RULES_ENV,
    _ARCH_NORMALIZE,
    _ARCH_RE,
    _normalize_arch,
    _normalize_file_type,
    _parse_die_report,
    compute_sha256,
    run_die,
    run_yara,
)
from analyzers.unpack import (
    CLEAN_SUFFIX,
    DOTNET_DECOMPILE_TIMEOUT_SECONDS,
    DOTNET_TOOL_TIMEOUT_SECONDS,
    PYTHON_TOOL_TIMEOUT_SECONDS,
    UNPACKED_SUFFIX,
    UPX_TIMEOUT_SECONDS,
    _decompile_pyc,
    _extract_dotnet_source,
    _extract_python_source,
    _find_main_pyc,
    _run_tool,
    _run_upx_unpack,
)
from ghidra_runner import run_ghidra
from import_combos import IMPORT_COMBO_RULES
from state import AgentState, DecompiledFunction, Finding, RouteFlag

logger = logging.getLogger(__name__)


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
# Deterministic IoC extraction
# --------------------------------------------------------------------------- #
def ioc_extractor_node(state: AgentState) -> dict[str, Any]:
    """Extracts IoCs (IP, URL, domain, ...) from FLOSS strings, deterministically.

    The LLM is not used for IoC extraction; ``filter_iocs`` decides.
    """
    logger.info("[ioc_extractor_node]")
    # IoC extraction is deterministic (filter_iocs); it is not left to the LLM.
    iocs = dict(state.iocs)
    iocs.setdefault("ioc", _unique([s for s in state.extracted_strings if filter_iocs([s])]))
    return {"iocs": iocs}


ai_extractor_agent = ioc_extractor_node  # backward-compatible name


# --------------------------------------------------------------------------- #
# LLM layer nodes (provider-agnostic: Ollama / vLLM / OpenAI-compatible)
# --------------------------------------------------------------------------- #
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

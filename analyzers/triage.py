"""Triage helpers: SHA-256 identity, DIE (Detect It Easy) reporting and YARA scanning."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import subprocess
from typing import Any

logger = logging.getLogger(__name__)

DIE_TIMEOUT_SECONDS = int(os.environ.get("CROWBAR_DIE_TIMEOUT", "60"))
SHA256_CHUNK_SIZE = 1024 * 1024  # 1 MiB
YARA_RULES_ENV = "CROWBAR_YARA_RULES"  # used by run_yara when rules_dir is not given

# YARA rule meta field for treating a rule as "definitely known malware" (e.g. meta: confidence = "known_malware")
KNOWN_MALWARE_META_KEY = "classification"
KNOWN_MALWARE_META_VALUE = "known_malware"


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

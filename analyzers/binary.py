"""Binary static-feature helpers (imports, entropy, PE metadata, import combos)."""

from __future__ import annotations

import hashlib
import logging
import math
import os
import re
import subprocess
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

from analyzers.common import _unique
from import_combos import IMPORT_COMBO_RULES
from state import Finding

logger = logging.getLogger(__name__)


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

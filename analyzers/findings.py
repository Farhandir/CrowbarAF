"""Finding construction, identity and integrity checks (verified IoCs)."""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from analyzers.binary import HIGH_ENTROPY_THRESHOLD
from analyzers.capa_floss import _capa_is_trivial, _ioc_kind
from state import Finding

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# findings
# --------------------------------------------------------------------------- #
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

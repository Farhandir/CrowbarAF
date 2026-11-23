"""capa / FLOSS execution and IoC string helpers."""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from typing import Any

from analyzers.common import _unique

logger = logging.getLogger(__name__)

CAPA_TIMEOUT_SECONDS = int(os.environ.get("CROWBAR_CAPA_TIMEOUT", "300"))
FLOSS_TIMEOUT_SECONDS = int(os.environ.get("CROWBAR_FLOSS_TIMEOUT", "300"))
CAPA_RULES_ENV = "CAPA_RULES"  # rule directory for capa -r; if empty, capa's built-in rules are tried


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


def _ioc_kind(text: str) -> str:
    """Determines the type of a FLOSS IoC string: url | ip | registry | file."""
    if _URL_RE.search(text):
        return "url"
    if _IPV4_RE.search(text):
        return "ip"
    if _REGISTRY_RE.search(text):
        return "registry"
    return "file"


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


# --------------------------------------------------------------------------- #
# capa
# --------------------------------------------------------------------------- #
TRIVIAL_CAPA_RULES = {"contain loop"}


def _capa_is_trivial(rule) -> bool:
    return str(rule).strip().lower() in TRIVIAL_CAPA_RULES


def _filter_trivial_capa(capabilities, hints):
    caps = dict(capabilities or {})
    caps["matched_rules"] = [r for r in (caps.get("matched_rules") or [])
                             if not _capa_is_trivial(r)]
    kept = [h for h in (hints or []) if not _capa_is_trivial(h.get("rule", ""))]
    return caps, kept


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

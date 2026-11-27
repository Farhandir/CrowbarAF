"""Per-method decompiled functions for .NET assemblies.

``dotnet_methods`` provides the metadata call graph/strings and ``dotnet_source`` splits the
ILSpy project output into C# members.  This module joins both views into one
``DecompiledFunction`` per MethodDef, scores it like the Ghidra/export_functions path and keeps
only the methods the LLM budget can afford.  Samples are never executed.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any

from analyzers.dotnet_methods import DotnetMethod, extract_dotnet_methods
from analyzers.dotnet_source import CSharpMember, run_ilspy_project, split_csharp_members
from analyzers.unpack import DOTNET_DECOMPILE_TIMEOUT_SECONDS
from export_functions import (
    CAPA_HIT_BONUS,
    DANGEROUS_API_BONUS,
    IOC_KINDS,
    IOC_REFERENCE_BONUS,
    LARGE_FUNCTION_BYTES,
    LARGE_FUNCTION_PENALTY,
    MAX_IOCS_PER_FUNCTION,
    MAX_STUBS,
    MIN_IOC_LENGTH,
    propagate_priority,
)
from state import DecompiledFunction, Finding

logger = logging.getLogger(__name__)

# Lowercase substrings matched against the lowercased API reference.
DOTNET_DANGEROUS_APIS = (
    "process::start",
    "assembly::load",
    "methodinfo::invoke",
    "methodbase::invoke",
    "activator::createinstance",
    "webclient::download",
    "webclient::upload",
    "httpclient::",
    "webrequest::create",
    "socket::",
    "tcpclient::",
    "registrykey::setvalue",
    "registry::setvalue",
    "file::writeallbytes",
    "file::delete",
    "file::copy",
    "convert::frombase64string",
    "cryptostream",
    "rijndael",
    "aes::create",
    "marshal::copy",
    "marshal::getdelegateforfunctionpointer",
    "virtualalloc",
    "virtualprotect",
    "createremotethread",
    "writeprocessmemory",
    "loadlibrary",
    "getprocaddress",
    "setwindowshookex",
    "getasynckeystate",
    "clipboard::",
)

MAX_CALLEES = 50
MAX_XREFS = 50
MAX_CODE_CHARS = 60_000
# Evidence-bearing methods may exceed the budget, but only by this many (obfuscated samples).
MAX_MUST_INCLUDE_EXTRA = 100

_NO_MEMBER_WARNING = "dotnet: no matching C# member"
_BUDGET_WARNING = "dotnet: not selected (budget)"
_TRUNCATED_WARNING = "dotnet: code truncated"


@dataclass
class _Record:
    """Mutable per-method record used while matching, scoring and selecting."""

    method: DotnetMethod
    index: int
    member: CSharpMember | None
    matched: bool
    c_code: str
    warnings: list[str] = field(default_factory=list)
    capa_hits: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    api_refs: list[str] = field(default_factory=list)
    callees: list[str] = field(default_factory=list)
    xrefs: list[str] = field(default_factory=list)
    is_library: bool = False
    priority: int = 0

    @property
    def token(self) -> int:
        return self.method.token

    @property
    def offset(self) -> str:
        return hex(self.method.token)

    def to_function(self) -> DecompiledFunction:
        return DecompiledFunction(
            offset=self.offset,
            size=self.method.il_size,
            is_library=self.is_library,
            callees=list(self.callees),
            xrefs=list(self.xrefs),
            decompile_warnings=list(self.warnings),
            name=self.method.full_name,
            priority=self.priority,
            c_code=self.c_code,
            capa_hits=list(self.capa_hits),
            iocs=list(self.iocs),
        )


def _append_unique(items: list[str], values: list[str], limit: int | None = None) -> None:
    """Appends values once, preserving order and optionally respecting ``limit``."""
    for value in values:
        if limit is not None and len(items) >= limit:
            return
        if value not in items:
            items.append(value)


def _add_warning(record: _Record, warning: str) -> None:
    if warning not in record.warnings:
        record.warnings.append(warning)


def _finding_field(finding: Finding | dict[str, Any], name: str, default: Any = "") -> Any:
    if isinstance(finding, dict):
        return finding.get(name, default)
    return getattr(finding, name, default)


def _parse_offset(value: Any) -> int | None:
    """Parses a hint offset (``"0x06000002"``, ``"0x6000002"``, ``18``) as an int."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text, 10)
    except ValueError:
        return None


def _hint_matches(value: Any, token: int) -> bool:
    parsed = _parse_offset(value)
    if parsed is not None:
        return parsed == token
    return str(value).strip().lower() == hex(token)


def _capa_hits_for_token(token: int, hints: list[dict[str, Any]] | None) -> list[str]:
    hits: list[str] = []
    for hint in hints or []:
        if not isinstance(hint, dict):
            continue
        rule = hint.get("rule")
        if not isinstance(rule, str) or not rule:
            continue
        if _hint_matches(hint.get("offset"), token):
            _append_unique(hits, [rule])
    return hits


def _collect_ioc_values(findings: list[Finding] | None) -> list[str]:
    values: list[str] = []
    for finding in findings or []:
        kind = str(_finding_field(finding, "kind")).lower()
        if kind not in IOC_KINDS:
            continue
        value = _finding_field(finding, "value")
        if not isinstance(value, str):
            continue
        value = value.strip()
        if len(value) < MIN_IOC_LENGTH:
            continue
        _append_unique(values, [value])
    return values


def _matching_iocs(strings: list[str], ioc_values: list[str]) -> list[str]:
    lowered = [text.lower() for text in strings if isinstance(text, str)]
    hits: list[str] = []
    for value in ioc_values:
        if len(hits) >= MAX_IOCS_PER_FUNCTION:
            break
        needle = value.lower()
        if any(needle in text for text in lowered):
            _append_unique(hits, [value], MAX_IOCS_PER_FUNCTION)
    return hits


def _has_dangerous_api(api_refs: list[str]) -> bool:
    for reference in api_refs:
        lowered = reference.lower()
        if any(needle in lowered for needle in DOTNET_DANGEROUS_APIS):
            return True
    return False


def _angle_content(text: str) -> str:
    """Returns the text inside the first ``<...>`` pair (empty when absent)."""
    start = text.find("<")
    if start < 0:
        return ""
    end = text.find(">", start + 1)
    if end < 0:
        return ""
    return text[start + 1 : end].strip()


def _generated_parent_name(method: DotnetMethod) -> str:
    """Parent method name from a generated type segment or the generated method name."""
    for segment in method.type_name.split("+"):
        name = _angle_content(segment)
        if name:
            return name
    return _angle_content(method.name)


def _generated_parent_type(type_name: str) -> str:
    """Removes generated ``+<...>...`` type segments (``Ns.Outer+<Run>d__5`` -> ``Ns.Outer``)."""
    parts = [part for part in type_name.split("+") if not part.startswith("<")]
    return "+".join(parts)


def _build_records(
    methods: list[DotnetMethod],
    members: list[CSharpMember],
    ghidra_hints: list[dict[str, Any]],
    findings: list[Finding],
) -> list[_Record]:
    by_key: dict[tuple[str, str, int], list[CSharpMember]] = {}
    for member in members:
        key = (member.type_name, member.name, member.param_count)
        by_key.setdefault(key, []).append(member)
    used: dict[tuple[str, str, int], int] = {}

    ioc_values = _collect_ioc_values(findings)
    records: list[_Record] = []
    for index, method in enumerate(methods):
        member: CSharpMember | None = None
        matched = False
        if not method.is_generated:
            key = (method.type_name, method.name, method.param_count)
            bucket = by_key.get(key, [])
            position = used.get(key, 0)
            if position < len(bucket):
                member = bucket[position]
                used[key] = position + 1
                matched = True

        warnings: list[str] = []
        c_code = ""
        if matched and member is not None:
            c_code = member.code
        elif not method.is_generated:
            warnings.append(_NO_MEMBER_WARNING)

        record = _Record(
            method=method,
            index=index,
            member=member,
            matched=matched,
            c_code=c_code,
            warnings=warnings,
            capa_hits=_capa_hits_for_token(method.token, ghidra_hints),
            iocs=_matching_iocs(list(method.strings), ioc_values),
            api_refs=list(method.api_refs),
            is_library=method.is_generated,
        )
        records.append(record)

    # Generated methods (lambdas, async/iterator state machines) have no C# block of their
    # own; ILSpy inlines their logic into the parent.  Move their evidence to the parent.
    parents: dict[tuple[str, str], _Record] = {}
    for record in records:
        if not record.method.is_generated:
            parents.setdefault((record.method.type_name, record.method.name), record)

    for record in records:
        if not record.method.is_generated:
            continue
        parent_name = _generated_parent_name(record.method)
        if not parent_name:
            continue
        parent = parents.get((_generated_parent_type(record.method.type_name), parent_name))
        if parent is None:
            continue
        _append_unique(parent.capa_hits, record.capa_hits)
        _append_unique(parent.iocs, record.iocs, MAX_IOCS_PER_FUNCTION)
        _append_unique(parent.api_refs, record.api_refs)
        record.capa_hits = []
        record.iocs = []
        record.api_refs = []

    return records


def _build_call_graph(records: list[_Record]) -> None:
    known = {record.token for record in records}
    callers: dict[int, list[str]] = {}
    for record in records:
        record.callees = [hex(token) for token in record.method.callees if token in known][:MAX_CALLEES]
        for token in record.method.callees:
            if token in known:
                callers.setdefault(token, []).append(record.offset)
    for record in records:
        record.xrefs = callers.get(record.token, [])[:MAX_XREFS]


def _compute_priorities(records: list[_Record]) -> None:
    for record in records:
        if record.is_library:
            record.priority = 0
            continue
        priority = 0
        if record.capa_hits:
            priority += CAPA_HIT_BONUS
        if record.iocs:
            priority += IOC_REFERENCE_BONUS
        if _has_dangerous_api(record.api_refs):
            priority += DANGEROUS_API_BONUS
        if record.method.il_size > LARGE_FUNCTION_BYTES:
            priority -= LARGE_FUNCTION_PENALTY
        record.priority = max(priority, 0)

    propagated = [
        {
            "offset": record.offset,
            "priority": record.priority,
            "callees": record.callees,
            "is_library": record.is_library,
        }
        for record in records
    ]
    propagate_priority(propagated, hops=2)
    for record, value in zip(records, propagated, strict=True):
        record.priority = value["priority"]


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default


def _selection_limit(count: int) -> int:
    mode = os.environ.get("CROWBAR_DECOMPILE_MODE", "top").strip().lower()
    if mode == "all":
        return max(1, count)
    if mode == "auto":
        auto_all = _env_int("CROWBAR_AUTO_ALL_CAP", 300)
        auto_top = _env_int("CROWBAR_AUTO_TOP_N", 300)
        return max(1, count if count <= auto_all else auto_top)
    return max(1, _env_int("CROWBAR_MAX_DECOMPILE", 100))


def _select(records: list[_Record]) -> tuple[set[int], list[_Record]]:
    candidates = [record for record in records if not record.is_library and record.matched]
    ranked = sorted(candidates, key=lambda record: (-record.priority, record.index))
    selected: set[int] = set()

    limit = _selection_limit(len(candidates)) if candidates else 0
    # Evidence-bearing methods are always analyzed, even beyond the budget.
    must_cap = limit + MAX_MUST_INCLUDE_EXTRA
    for record in ranked:
        if len(selected) >= must_cap:
            logger.warning("[dotnet_functions] must-include cap of %d reached", must_cap)
            break
        if record.capa_hits or record.iocs:
            selected.add(record.token)
    for record in ranked:
        if len(selected) >= limit:
            break
        selected.add(record.token)

    for record in records:
        if record.is_library or not record.matched or record.token in selected:
            continue
        record.c_code = ""
        _add_warning(record, _BUDGET_WARNING)

    selected_records = [record for record in records if record.token in selected]
    return selected, selected_records


def _collect_output(records: list[_Record], selected: set[int]) -> tuple[list[_Record], list[_Record]]:
    selected_records = [record for record in records if record.token in selected]
    by_offset = {record.offset: record for record in records}
    seen = set(selected)
    stubs: list[_Record] = []

    for record in selected_records:
        for callee in record.callees:
            if len(stubs) >= MAX_STUBS:
                break
            target = by_offset.get(callee)
            if target is None or target.token in seen:
                continue
            seen.add(target.token)
            stubs.append(target)

    output = selected_records + stubs
    for record in output:
        if len(record.c_code) > MAX_CODE_CHARS:
            record.c_code = record.c_code[:MAX_CODE_CHARS]
            _add_warning(record, _TRUNCATED_WARNING)
    output.sort(key=lambda record: (-record.priority, record.token))
    return output, stubs


def _build(
    file_path: str,
    ghidra_hints: list[dict[str, Any]],
    findings: list[Finding],
    timeout: int,
) -> list[DecompiledFunction] | None:
    methods = [method for method in extract_dotnet_methods(file_path) if method.has_body]
    if not methods:
        return None

    files = run_ilspy_project(file_path, timeout)
    if not files:
        return None
    members = split_csharp_members(files)

    records = _build_records(methods, members, ghidra_hints, findings)
    matched = sum(1 for record in records if record.matched)
    if matched == 0:
        return None

    _build_call_graph(records)
    _compute_priorities(records)
    selected, selected_records = _select(records)
    output, stubs = _collect_output(records, selected)

    logger.info(
        "[dotnet_functions] methods=%d matched=%d selected=%d stubs=%d",
        len(methods),
        matched,
        len(selected_records),
        len(stubs),
    )
    return [record.to_function() for record in output]


def build_dotnet_functions(
    file_path: str,
    ghidra_hints: list[dict[str, Any]],
    findings: list[Finding],
    timeout: int = DOTNET_DECOMPILE_TIMEOUT_SECONDS,
) -> list[DecompiledFunction] | None:
    """Builds one scored ``DecompiledFunction`` per .NET MethodDef.

    Returns ``None`` when the per-method path is unusable (no methods with a body, ILSpy
    failed, or no method could be matched to a C# member) so callers can fall back.  Never
    raises.
    """
    try:
        return _build(file_path, ghidra_hints, findings, timeout)
    except Exception as exc:  # noqa: BLE001 - the analysis workflow must never crash
        logger.warning("[dotnet_functions] per-method build failed: %s: %s", type(exc).__name__, exc)
        return None

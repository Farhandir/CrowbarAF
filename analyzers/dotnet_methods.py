"""Static .NET metadata / IL reader: MethodDefs, call graph, API refs and strings.

The module only parses bytes with ``dnfile`` + ``dncil``; samples are never executed.
Every public entry point is fail-open: on unexpected input it logs a warning and
returns whatever could be collected (or an empty list).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import dnfile
from dncil.cil.body import CilMethodBody
from dncil.cil.body.reader import CilMethodBodyReaderBase
from dncil.cil.opcode import OpCodes

logger = logging.getLogger(__name__)

_METHODDEF_TABLE = 6
_MEMBERREF_TABLE = 10
_METHODSPEC_TABLE = 43
_IMPLMAP_TABLE = 28
_TYPEDEF_TABLE = 2
_TYPEREF_TABLE = 1
_NESTEDCLASS_TABLE = 41

_MAX_CALLEES = 200
_MAX_API_REFS = 200
_MAX_STRINGS = 200
_MAX_STRING_LENGTH = 500

_CALL_OPCODES = frozenset(
    {
        OpCodes.Call,
        OpCodes.Callvirt,
        OpCodes.Newobj,
        OpCodes.Ldftn,
        OpCodes.Ldvirtftn,
        OpCodes.Jmp,
    }
)

_GENERIC_ARITY_RE = re.compile(r"`\d+")


@dataclass
class DotnetMethod:
    """A single MethodDef with its internal calls, external APIs and user strings."""

    token: int
    type_name: str
    name: str
    param_count: int
    il_size: int
    callees: list[int] = field(default_factory=list)
    api_refs: list[str] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    is_generated: bool = False
    has_body: bool = False

    @property
    def full_name(self) -> str:
        return f"{self.type_name}::{self.name}"


class _DnfileMethodBodyReader(CilMethodBodyReaderBase):
    """Adapter that lets ``dncil`` read a method body through ``dnfile``."""

    def __init__(self, pe: dnfile.dnPE, row: Any):
        self.pe = pe
        self.offset = self.pe.get_offset_from_rva(row.Rva)

    def read(self, n: int) -> bytes:
        data = self.pe.get_data(self.pe.get_rva_from_offset(self.offset), n)
        self.offset += n
        return data

    def tell(self) -> int:
        return self.offset

    def seek(self, offset: int) -> int:
        self.offset = offset
        return self.offset


def _text(value: Any) -> str:
    """Returns a metadata string value as ``str`` (empty for ``None``)."""
    return "" if value is None else str(value)


def _strip_generic_arity(name: str) -> str:
    """Removes generic arity suffixes such as ``List`1`` -> ``List``."""
    return _GENERIC_ARITY_RE.sub("", name)


def _format_type_name(namespace: str, type_names: Sequence[str]) -> str:
    """Builds ``Namespace.Outer+Inner`` (namespace omitted when empty)."""
    joined = "+".join(name for name in type_names if name)
    if namespace and joined:
        return f"{namespace}.{joined}"
    return namespace or joined


def _nested_class_map(nested_rows: Sequence[Any]) -> dict[int, int]:
    """Maps a nested TypeDef row index to its enclosing TypeDef row index."""
    mapping: dict[int, int] = {}
    for row in nested_rows or ():
        try:
            nested = getattr(row, "NestedClass", None)
            enclosing = getattr(row, "EnclosingClass", None)
            nested_rid = getattr(nested, "row_index", None)
            enclosing_rid = getattr(enclosing, "row_index", None)
        except Exception:  # noqa: BLE001 - malformed metadata must not stop the scan
            continue
        if isinstance(nested_rid, int) and isinstance(enclosing_rid, int) and nested_rid and enclosing_rid:
            mapping[nested_rid] = enclosing_rid
    return mapping


def _build_typedef_names(typedef_rows: Sequence[Any], nested_rows: Sequence[Any]) -> dict[int, str]:
    """Resolves every TypeDef row index to ``Namespace.Outer+Inner`` (generic arity stripped)."""
    rows_by_rid = {rid: row for rid, row in enumerate(typedef_rows or (), 1)}
    nested_map = _nested_class_map(nested_rows)

    names: dict[int, str] = {}
    for rid, row in rows_by_rid.items():
        names[rid] = _format_type_name(
            _text(getattr(row, "TypeNamespace", "")),
            [_strip_generic_arity(_text(getattr(row, "TypeName", "")))],
        )

    for rid in nested_map:
        if rid not in rows_by_rid:
            continue

        parts: list[str] = []
        seen: set[int] = set()
        current = rid
        root_rid = rid
        while current in nested_map and current not in seen:
            seen.add(current)
            row = rows_by_rid.get(current)
            if row is not None:
                parts.append(_strip_generic_arity(_text(getattr(row, "TypeName", ""))))
            current = nested_map[current]
            root_rid = current

        root = rows_by_rid.get(root_rid)
        if root is None:
            continue
        parts.append(_strip_generic_arity(_text(getattr(root, "TypeName", ""))))
        names[rid] = _format_type_name(
            _text(getattr(root, "TypeNamespace", "")),
            list(reversed(parts)),
        )

    return names


def _method_owner_map(typedef_rows: Sequence[Any]) -> dict[int, int]:
    """Maps MethodDef row indices to the TypeDef row index that owns them."""
    owners: dict[int, int] = {}
    for type_rid, row in enumerate(typedef_rows or (), 1):
        method_list = getattr(row, "MethodList", None) or ()
        for index in method_list:
            method_rid = index if isinstance(index, int) else getattr(index, "row_index", None)
            if isinstance(method_rid, int) and method_rid > 0:
                owners.setdefault(method_rid, type_rid)
    return owners


def _count_params(method_row: Any) -> int:
    """Counts declared parameters whose Sequence is greater than zero (return rows are 0)."""
    params = getattr(method_row, "ParamList", None) or ()
    count = 0
    for index in params:
        try:
            row = getattr(index, "row", None)
            sequence = getattr(row, "Sequence", None)
            if sequence is None:
                sequence = getattr(index, "Sequence", None)
        except Exception:  # noqa: BLE001 - broken Param references are ignored
            continue
        if isinstance(sequence, int) and sequence > 0:
            count += 1
    return count


def _has_il_body(method_row: Any) -> bool:
    """Whether the MethodDef advertises a readable IL body."""
    try:
        if not getattr(method_row, "Rva", 0):
            return False
    except Exception:  # noqa: BLE001 - unreadable rows simply have no body
        return False

    flags = getattr(method_row, "Flags", None)
    if getattr(flags, "mdAbstract", False):
        return False

    impl_flags = getattr(method_row, "ImplFlags", None)
    if getattr(impl_flags, "miRuntime", False) or getattr(impl_flags, "miInternalCall", False):
        return False

    return True


def _table_row(tables: Mapping[int, Any], table_number: int, rid: Any) -> Any | None:
    """Returns a 1-based metadata table row, or ``None`` when it cannot be resolved."""
    if not isinstance(rid, int) or rid <= 0:
        return None
    try:
        table = tables.get(table_number)
    except Exception:  # noqa: BLE001 - malformed table map
        return None
    if table is None:
        return None
    try:
        return table[rid - 1]
    except (IndexError, KeyError, TypeError):
        return None


def _resolve_typeref_name(typeref_row: Any, tables: Mapping[int, Any]) -> str:
    """Resolves a possibly nested TypeRef to ``Namespace.Outer+Inner``."""
    if typeref_row is None:
        return ""

    parts: list[str] = []
    seen: set[int] = set()
    current = typeref_row
    root = typeref_row

    while current is not None and id(current) not in seen:
        seen.add(id(current))
        parts.append(_strip_generic_arity(_text(getattr(current, "TypeName", ""))))
        root = current

        resolution_scope = getattr(current, "ResolutionScope", None)
        scope_table = getattr(resolution_scope, "table", None)
        if _text(getattr(scope_table, "name", "")) != "TypeRef":
            break
        current = _table_row(tables, _TYPEREF_TABLE, getattr(resolution_scope, "row_index", None))

    namespace = _text(getattr(root, "TypeNamespace", "")) or _text(
        getattr(typeref_row, "TypeNamespace", "")
    )
    return _format_type_name(namespace, list(reversed(parts)))


def _memberref_api_ref(memberref_row: Any, tables: Mapping[int, Any]) -> str | None:
    """Builds ``Namespace.Type::Member`` for a MemberRef row."""
    if memberref_row is None:
        return None

    member = _strip_generic_arity(_text(getattr(memberref_row, "Name", "")))
    if not member:
        return None

    parent = getattr(memberref_row, "Class", None)
    parent_table = getattr(parent, "table", None)
    parent_table_name = _text(getattr(parent_table, "name", ""))
    parent_row = getattr(parent, "row", None)
    if parent_table_name == "TypeSpec" or parent_row is None:
        return f"?::{member}"

    if parent_table_name == "TypeRef":
        type_name = _resolve_typeref_name(parent_row, tables)
    elif parent_table_name == "TypeDef":
        type_name = _format_type_name(
            _text(getattr(parent_row, "TypeNamespace", "")),
            [_strip_generic_arity(_text(getattr(parent_row, "TypeName", "")))],
        )
    else:
        type_name = ""

    return f"{type_name}::{member}" if type_name else f"?::{member}"


def _build_pinvoke_map(impl_map_rows: Sequence[Any]) -> dict[int, str]:
    """Maps MethodDef row indices to ``<module>!<import name>`` for P/Invoke methods."""
    mapping: dict[int, str] = {}
    for row in impl_map_rows or ():
        try:
            forwarded = getattr(row, "MemberForwarded", None)
            forwarded_table = getattr(forwarded, "table", None)
            if getattr(forwarded_table, "number", None) != _METHODDEF_TABLE:
                continue
            method_rid = getattr(forwarded, "row_index", None)
            import_name = _text(getattr(row, "ImportName", ""))
            if not isinstance(method_rid, int) or method_rid <= 0 or not import_name:
                continue

            module = ""
            import_scope = getattr(row, "ImportScope", None)
            scope_row = getattr(import_scope, "row", None)
            if scope_row is not None:
                module = _text(getattr(scope_row, "Name", ""))
            mapping[method_rid] = f"{module}!{import_name}"
        except Exception:  # noqa: BLE001 - malformed ImplMap rows are skipped
            continue
    return mapping


def _resolve_call_token(
    token: Any,
    tables: Mapping[int, Any],
    pinvoke_map: Mapping[int, str],
) -> tuple[int | None, str | None]:
    """Resolves a call operand to ``(internal MethodDef rid, external API string)``."""
    table_number = getattr(token, "table", None)
    rid = getattr(token, "rid", None)

    if table_number == _METHODDEF_TABLE:
        if isinstance(rid, int) and rid > 0:
            return rid, pinvoke_map.get(rid)
        return None, None

    if table_number == _MEMBERREF_TABLE:
        memberref_row = _table_row(tables, _MEMBERREF_TABLE, rid)
        return None, _memberref_api_ref(memberref_row, tables)

    if table_number == _METHODSPEC_TABLE:
        methodspec_row = _table_row(tables, _METHODSPEC_TABLE, rid)
        if methodspec_row is None:
            return None, None
        method = getattr(methodspec_row, "Method", None)
        method_table = getattr(method, "table", None)
        method_table_number = getattr(method_table, "number", None)
        method_rid = getattr(method, "row_index", None)

        if method_table_number == _METHODDEF_TABLE:
            if isinstance(method_rid, int) and method_rid > 0:
                return method_rid, pinvoke_map.get(method_rid)
            return None, None
        if method_table_number == _MEMBERREF_TABLE:
            memberref_row = _table_row(tables, _MEMBERREF_TABLE, method_rid)
            return None, _memberref_api_ref(memberref_row, tables)

    return None, None


def _read_user_string(user_strings: Any, token: Any) -> str | None:
    """Reads an ``ldstr`` user string from the #US stream; returns ``None`` on failure."""
    if user_strings is None or token is None:
        return None

    rid = getattr(token, "rid", None)
    if not isinstance(rid, int):
        return None

    try:
        item = user_strings.get(rid)
    except (UnicodeDecodeError, IndexError, KeyError, TypeError, ValueError):
        return None
    except Exception:  # noqa: BLE001 - obfuscated #US streams can raise anything
        return None

    value = getattr(item, "value", None)
    return value if isinstance(value, str) else None


def _append_unique(items: list[Any], value: Any, limit: int) -> None:
    """Appends ``value`` once, preserving order, while respecting a hard limit."""
    if len(items) >= limit or value in items:
        return
    items.append(value)


def _methoddef_token(rid: int) -> int:
    """Full metadata token for a MethodDef row index."""
    return (_METHODDEF_TABLE << 24) | (rid & 0xFFFFFF)


def _instruction_bytes(instructions: Sequence[Any]) -> int:
    total = 0
    for instruction in instructions:
        size = getattr(instruction, "size", 0)
        if isinstance(size, int):
            total += size
    return total


def _analyze_method(
    method_row: Any,
    token: int,
    type_name: str,
    tables: Mapping[int, Any],
    user_strings: Any,
    pinvoke_map: Mapping[int, str],
    body: Any | None,
) -> DotnetMethod:
    """Builds a ``DotnetMethod`` from an already loaded row and decoded body."""
    name = _text(getattr(method_row, "Name", ""))
    callees: list[int] = []
    api_refs: list[str] = []
    strings: list[str] = []

    has_body = body is not None
    il_size = 0
    instructions: Sequence[Any] = ()
    if has_body:
        instructions = getattr(body, "instructions", None) or ()
        code_size = getattr(body, "code_size", None)
        il_size = code_size if isinstance(code_size, int) else _instruction_bytes(instructions)

    for instruction in instructions:
        try:
            opcode = getattr(instruction, "opcode", None)
            operand = getattr(instruction, "operand", None)

            if opcode in _CALL_OPCODES:
                callee, api_ref = _resolve_call_token(operand, tables, pinvoke_map)
                if callee is not None:
                    # Store the full MethodDef token (0x06xxxxxx) so callees match ``token``.
                    _append_unique(callees, _methoddef_token(callee), _MAX_CALLEES)
                if api_ref:
                    _append_unique(api_refs, api_ref, _MAX_API_REFS)

            elif opcode is OpCodes.Ldstr:
                text = _read_user_string(user_strings, operand)
                if text is not None:
                    _append_unique(strings, text[:_MAX_STRING_LENGTH], _MAX_STRINGS)
        except Exception as exc:  # noqa: BLE001 - one bad instruction must not drop the method
            logger.debug(
                "[dotnet_methods] failed to process an instruction in token 0x%08X: %s: %s",
                token,
                type(exc).__name__,
                exc,
            )

    return DotnetMethod(
        token=token,
        type_name=type_name,
        name=name,
        param_count=_count_params(method_row),
        il_size=il_size,
        callees=callees,
        api_refs=api_refs,
        strings=strings,
        is_generated="<" in name or "<" in type_name,
        has_body=has_body,
    )


def _extract_from_tables(
    method_rows: Sequence[Any],
    typedef_rows: Sequence[Any],
    nested_rows: Sequence[Any],
    impl_map_rows: Sequence[Any],
    tables: Mapping[int, Any],
    user_strings: Any,
    body_loader: Callable[[Any], Any | None] | None,
    max_methods: int = 20000,
) -> list[DotnetMethod]:
    """Core extraction over already loaded metadata rows (testable without a PE file)."""
    methods: list[DotnetMethod] = []

    try:
        typedef_names = _build_typedef_names(typedef_rows, nested_rows)
        owners = _method_owner_map(typedef_rows)
        pinvoke_map = _build_pinvoke_map(impl_map_rows)
    except Exception as exc:  # noqa: BLE001 - malformed metadata must not crash the workflow
        logger.warning(
            "[dotnet_methods] failed to prepare metadata tables: %s: %s",
            type(exc).__name__,
            exc,
        )
        return methods

    for rid, method_row in enumerate(method_rows or (), 1):
        if len(methods) >= max_methods:
            logger.warning(
                "[dotnet_methods] method limit of %d reached; remaining methods are skipped",
                max_methods,
            )
            break

        token = _methoddef_token(rid)
        try:
            type_name = typedef_names.get(owners.get(rid, 0), "")

            body = None
            if body_loader is not None and _has_il_body(method_row):
                try:
                    body = body_loader(method_row)
                except Exception as exc:  # noqa: BLE001 - keep the method record without a body
                    logger.debug(
                        "[dotnet_methods] failed to parse the method body of token 0x%08X: %s: %s",
                        token,
                        type(exc).__name__,
                        exc,
                    )
                    body = None

            methods.append(
                _analyze_method(
                    method_row,
                    token,
                    type_name,
                    tables,
                    user_strings,
                    pinvoke_map,
                    body,
                )
            )
        except Exception as exc:  # noqa: BLE001 - one bad row must not stop the scan
            logger.warning(
                "[dotnet_methods] failed to analyze MethodDef token 0x%08X: %s: %s",
                token,
                type(exc).__name__,
                exc,
            )
            continue

    return methods


def _table_rows(tables: Mapping[int, Any], table_number: int) -> list[Any]:
    """Materialises a metadata table as a list (empty when the table is missing)."""
    try:
        table = tables.get(table_number)
        if table is None:
            return []
        return list(table)
    except Exception:  # noqa: BLE001 - broken tables are treated as absent
        return []


def _read_method_body(pe: dnfile.dnPE, row: Any) -> CilMethodBody | None:
    """Parses one managed method body; returns ``None`` on any format problem."""
    try:
        return CilMethodBody(_DnfileMethodBodyReader(pe, row))
    except Exception as exc:  # noqa: BLE001 - body parse errors are expected in obfuscated samples
        logger.debug(
            "[dotnet_methods] failed to parse method body @ RVA 0x%X: %s: %s",
            getattr(row, "Rva", 0),
            type(exc).__name__,
            exc,
        )
        return None


def extract_dotnet_methods(path: str, max_methods: int = 20000) -> list[DotnetMethod]:
    """Returns all MethodDefs of a .NET assembly; ``[]`` when the file is not readable .NET.

    Never raises. The result keeps metadata table order and is capped at ``max_methods``.
    """
    pe: dnfile.dnPE | None = None
    try:
        pe = dnfile.dnPE(path)

        net = getattr(pe, "net", None)
        if net is None:
            return []
        mdtables = getattr(net, "mdtables", None)
        if mdtables is None:
            return []
        tables = getattr(mdtables, "tables", None) or {}

        method_rows = _table_rows(tables, _METHODDEF_TABLE)
        if not method_rows:
            return []

        return _extract_from_tables(
            method_rows=method_rows,
            typedef_rows=_table_rows(tables, _TYPEDEF_TABLE),
            nested_rows=_table_rows(tables, _NESTEDCLASS_TABLE),
            impl_map_rows=_table_rows(tables, _IMPLMAP_TABLE),
            tables=tables,
            user_strings=getattr(net, "user_strings", None),
            body_loader=lambda row: _read_method_body(pe, row),
            max_methods=max_methods,
        )
    except Exception as exc:  # noqa: BLE001 - the analysis workflow must never crash
        logger.warning(
            "[dotnet_methods] failed to read %s: %s: %s",
            path,
            type(exc).__name__,
            exc,
        )
        return []
    finally:
        if pe is not None:
            try:
                pe.close()
            except Exception:  # noqa: BLE001 - close errors are irrelevant to the result
                pass

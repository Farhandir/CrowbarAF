"""Per-member C# source blocks from ILSpy (``ilspycmd -p``) output.

The ILSpy project writer emits one ``.cs`` file per top-level type.  This module runs
``ilspycmd`` and splits that C# into the individual members (methods, constructors,
property/event accessors, operators) whose names are normalized to .NET metadata names
(``.ctor``, ``get_X``, ``set_X``, ``add_X``, ``op_Addition`` ...), so they can later be
matched to metadata methods by type name, member name and parameter count.

Structure tracking is character based: comments, regular/verbatim/interpolated/raw string
literals and char literals are masked before braces are counted.  Indentation alone is
never trusted.

Nothing here executes the analyzed assembly; ``ilspycmd`` only decompiles bytes.
"""

from __future__ import annotations

import logging
import os
import re
import tempfile
import textwrap
from dataclasses import dataclass

from analyzers.unpack import _run_tool

logger = logging.getLogger(__name__)

MAX_SOURCE_FILE_BYTES = 5 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 50 * 1024 * 1024

_TYPE_KEYWORDS = frozenset({"class", "struct", "interface", "enum", "record", "delegate"})
_TYPE_MODIFIERS = frozenset(
    {
        "public",
        "private",
        "protected",
        "internal",
        "static",
        "sealed",
        "abstract",
        "partial",
        "readonly",
        "unsafe",
        "new",
        "file",
        "ref",
        "extern",
        "volatile",
        "override",
        "virtual",
        "async",
        "fixed",
        "required",
        "scoped",
    }
)
_ACCESSOR_PARAMS = {"get": 0, "set": 1, "init": 1, "add": 1, "remove": 1}
_SET_ACCESSORS = frozenset({"set", "init"})
_OPERATOR_NAMES = {
    "+": "op_Addition",
    "-": "op_Subtraction",
    "==": "op_Equality",
    "!=": "op_Inequality",
}
_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass
class CSharpMember:
    """One C# member block extracted from ILSpy output."""

    type_name: str  # "Namespace.Outer+Inner" (generic parameters removed)
    name: str  # metadata-style member name (".ctor", "get_Item", "op_Addition", ...)
    param_count: int
    code: str  # member text (attributes + signature + body), dedented
    file: str  # relative path of the .cs file
    start_line: int  # 1-based


# ---------------------------------------------------------------------------
# Character scanner: mask literals and comments
# ---------------------------------------------------------------------------


def _scan_char(text: str, start: int) -> int | None:
    """Returns the index just after the char literal starting at ``start``, or ``None``."""
    n = len(text)
    i = start + 1
    if i >= n:
        return None
    if text[i] == "\\":
        i += 1
        while i < n and text[i] != "'":
            if text[i] == "\n":
                return None
            i += 1
    else:
        if text[i] in "'\n":
            return None
        i += 1
    if i < n and text[i] == "'":
        return i + 1
    return None


def _skip_interpolation_hole(text: str, start: int) -> int:
    """Skips the ``{ ... }`` hole of an interpolated string; returns the index after ``}``."""
    n = len(text)
    depth = 1
    i = start
    while i < n:
        ch = text[i]
        if ch == '"':
            end = _scan_literal(text, i)
            i = end if end is not None else i + 1
        elif ch == "'":
            end = _scan_char(text, i)
            i = end if end is not None else i + 1
        elif ch == "/" and i + 1 < n and text[i + 1] == "/":
            newline = text.find("\n", i)
            i = n if newline < 0 else newline
        elif ch == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
        elif ch == "{":
            depth += 1
            i += 1
        elif ch == "}":
            depth -= 1
            i += 1
            if depth == 0:
                return i
        else:
            i += 1
    return n


def _scan_literal(text: str, start: int) -> int | None:
    """Returns the index just after the string literal starting at ``start``, or ``None``.

    Supports regular, verbatim (``@``), interpolated (``$``) and raw (``\"\"\"``) strings,
    including the ``$@\"\"`` / ``@$\"\"`` combinations.
    """
    n = len(text)
    i = start
    dollars = 0
    while i < n and text[i] == "$":
        dollars += 1
        i += 1
    verbatim = False
    if i < n and text[i] == "@":
        verbatim = True
        i += 1
    while i < n and text[i] == "$":
        dollars += 1
        i += 1
    if i >= n or text[i] != '"':
        return None

    quote_start = i
    quotes = 0
    while i < n and text[i] == '"':
        quotes += 1
        i += 1
    if quotes >= 3:
        # Raw string literal: closes on a run of at least as many quotes.
        terminator = '"' * quotes
        end = text.find(terminator, i)
        return n if end < 0 else end + quotes

    k = quote_start + 1
    while k < n:
        ch = text[k]
        if verbatim:
            if ch == '"':
                if k + 1 < n and text[k + 1] == '"':
                    k += 2
                    continue
                return k + 1
        else:
            if ch == "\\":
                k += 2
                continue
            if ch == '"':
                return k + 1
        if dollars and ch == "{":
            if k + 1 < n and text[k + 1] == "{":
                k += 2
                continue
            k = _skip_interpolation_hole(text, k + 1)
            continue
        if dollars and ch == "}" and k + 1 < n and text[k + 1] == "}":
            k += 2
            continue
        k += 1
    return n


def _mask_source(text: str) -> str:
    """Replaces comments and literal contents with spaces, preserving length and newlines."""
    chars = list(text)
    n = len(text)
    i = 0
    while i < n:
        ch = text[i]
        end: int | None = None
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            end = text.find("\n", i)
            if end < 0:
                end = n
        elif ch == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            end = n if end < 0 else end + 2
        elif ch == "'":
            end = _scan_char(text, i)
        elif ch in '"$@':
            end = _scan_literal(text, i)
        if end is None:
            i += 1
            continue
        chars[i:end] = [c if c in "\r\n" else " " for c in text[i:end]]
        i = max(end, i + 1)
    return "".join(chars)


# ---------------------------------------------------------------------------
# Structure helpers
# ---------------------------------------------------------------------------


def _skip_space(text: str, start: int, limit: int) -> int:
    while start < limit and text[start].isspace():
        start += 1
    return start


def _previous_nonspace(text: str, index: int, floor: int) -> str:
    while index >= floor and text[index].isspace():
        index -= 1
    return text[index] if index >= floor else ""


def _match_pair(text: str, open_index: int, open_ch: str, close_ch: str, limit: int) -> int | None:
    depth = 0
    i = open_index
    while i < limit:
        if text[i] == open_ch:
            depth += 1
        elif text[i] == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _skip_attributes(text: str, start: int, limit: int) -> int:
    """Skips leading ``[Attribute]`` groups; returns the index of the declaration itself."""
    i = start
    while True:
        i = _skip_space(text, i, limit)
        if i < limit and text[i] == "[":
            close = _match_pair(text, i, "[", "]", limit)
            if close is None:
                return start
            i = close + 1
            continue
        return i


def _find_semicolon(text: str, start: int, limit: int) -> int:
    """Returns the index after the first top-level ``;`` (balanced by (), [], {}); else ``limit``."""
    paren = bracket = brace = 0
    i = start
    while i < limit:
        ch = text[i]
        if ch == "(":
            paren += 1
        elif ch == ")":
            paren = max(0, paren - 1)
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket = max(0, bracket - 1)
        elif ch == "{":
            brace += 1
        elif ch == "}":
            brace = max(0, brace - 1)
        elif ch == ";" and paren == 0 and bracket == 0 and brace == 0:
            return i + 1
        i += 1
    return limit


def _declaration(header_end: int, end: int, has_body: bool, expr: bool, body_open: int = -1, body_close: int = -1) -> dict:
    return {
        "header_end": header_end,
        "end": end,
        "has_body": has_body,
        "expr": expr,
        "body_open": body_open,
        "body_close": body_close,
    }


def _scan_declaration(text: str, start: int, limit: int) -> dict:
    """Finds one declaration's extent (header, optional body) starting at ``start``."""
    i = start
    paren = bracket = 0
    assignment = False
    while i < limit:
        ch = text[i]
        if ch == "(":
            paren += 1
        elif ch == ")":
            paren = max(0, paren - 1)
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket = max(0, bracket - 1)
        elif paren == 0 and bracket == 0:
            if ch == "{" and assignment:
                close = _match_pair(text, i, "{", "}", limit)
                i = limit if close is None else close + 1
                continue
            if ch == "{":
                close = _match_pair(text, i, "{", "}", limit)
                if close is None:
                    return _declaration(i, limit, True, False, i, limit)
                end = close + 1
                after = _skip_space(text, end, limit)
                if after < limit and text[after] == ";":
                    end = after + 1
                elif after < limit and text[after] == "=" and (after + 1 >= limit or text[after + 1] != ">"):
                    end = _find_semicolon(text, after + 1, limit)
                return _declaration(i, end, True, False, i, close)
            if ch == ";":
                return _declaration(i, i + 1, False, False)
            if ch == "=" and i + 1 < limit and text[i + 1] == ">":
                if not assignment:
                    return _declaration(i, _find_semicolon(text, i + 2, limit), False, True)
                i += 2
                continue
            if ch == "=" and not assignment:
                next_ch = text[i + 1] if i + 1 < limit else ""
                previous = _previous_nonspace(text, i - 1, start)
                if next_ch != "=" and previous not in "=!<>+-*/%&|^:":
                    assignment = True
        i += 1
    return _declaration(limit, limit, False, False)


def _decl_keyword(text: str, start: int, end: int) -> str | None:
    """Returns the declaration keyword (``class``, ``namespace`` ...) or ``None``."""
    i = _skip_attributes(text, start, end)
    for match in _IDENTIFIER_RE.finditer(text, i, end):
        word = match.group()
        if word in _TYPE_MODIFIERS:
            continue
        if word in _TYPE_KEYWORDS or word == "namespace":
            return word
        return None
    return None


def _simple_type_name(text: str, start: int, end: int, keyword: str) -> str:
    i = _skip_attributes(text, start, end)
    match = re.search(r"\b(?:class|struct|interface|enum|record|delegate)\b", text[i:end])
    if match is None:
        return ""
    words = _IDENTIFIER_RE.findall(text[i + match.end() : end])
    if keyword == "record" and words and words[0] in {"class", "struct"}:
        words = words[1:]
    return words[0] if words else ""


def _namespace_name(header: str) -> str:
    match = re.search(r"\bnamespace\b\s+([^\s{;]+)", header)
    return match.group(1) if match else ""


def _combine_namespace(outer: str, inner: str) -> str:
    if not outer:
        return inner
    if not inner:
        return outer
    return f"{outer}.{inner}"


def _count_params(params_text: str) -> int:
    """Counts top-level commas in a parameter list (nested generics/calls/arrays ignored)."""
    if not params_text.strip():
        return 0
    depth = 0
    count = 1
    for ch in params_text:
        if ch in "<([{":
            depth += 1
        elif ch in ">)]}":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            count += 1
    return count


def _strip_generics(text: str) -> str:
    previous = None
    while previous != text:
        previous = text
        text = re.sub(r"<[^<>]*>", "", text)
    return text


def _member_code(text: str, start: int, end: int) -> str:
    """Returns the dedented member text, starting from the beginning of its first line."""
    line_start = text.rfind("\n", 0, start) + 1
    if text[line_start:start].strip():
        line_start = start
    chunk = text[line_start:end].rstrip()
    if not chunk.strip():
        return ""
    return textwrap.dedent(chunk).strip("\n")


def _add_member(
    members: list[CSharpMember],
    file: str,
    text: str,
    start: int,
    end: int,
    type_name: str,
    name: str,
    param_count: int,
) -> None:
    code = _member_code(text, start, end)
    if not code or not name:
        return
    start_line = text.count("\n", 0, start) + 1
    members.append(CSharpMember(type_name, name, param_count, code, file, start_line))


# ---------------------------------------------------------------------------
# Member header parsing
# ---------------------------------------------------------------------------


def _find_param_open(signature: str) -> int | None:
    """Finds the opening paren of a method's parameter list in a masked header."""
    n = len(signature)
    i = 0
    while i < n:
        ch = signature[i]
        if ch == "[":
            close = _match_pair(signature, i, "[", "]", n)
            if close is None:
                return None
            i = close + 1
            continue
        if ch == "(":
            close = _match_pair(signature, i, "(", ")", n)
            if close is None:
                return None
            after = _skip_space(signature, close + 1, n)
            rest = signature[after:]
            if not rest.strip() or rest[0] in "{;=:" or rest.startswith("where"):
                return i
            i = close + 1
            continue
        i += 1
    return None


def _operator_name(name_part: str) -> str:
    if re.search(r"\bimplicit\b", name_part):
        return "op_Implicit"
    if re.search(r"\bexplicit\b", name_part):
        return "op_Explicit"
    match = re.search(r"\boperator\b", name_part)
    tail = name_part[match.end() :].strip() if match else ""
    symbol = tail.split()[0] if tail else ""
    return _OPERATOR_NAMES.get(symbol, "op_Unknown")


def _accessor_kind(header: str) -> str | None:
    words = _IDENTIFIER_RE.findall(header)
    for word in reversed(words):
        if word in _ACCESSOR_PARAMS:
            return word
    return None


def _accessor_params(kind: str, indexer_param_count: int) -> int:
    if kind == "get":
        return indexer_param_count
    if kind in _SET_ACCESSORS:
        return indexer_param_count + 1
    return _ACCESSOR_PARAMS[kind]


def _property_base_name(header: str) -> str:
    stripped = header.rstrip()
    if re.search(r"\bthis\s*\[", stripped):
        return "Item"
    words = _IDENTIFIER_RE.findall(stripped)
    return words[-1].lstrip("@") if words else ""


def _extract_accessors(
    members: list[CSharpMember],
    file: str,
    text: str,
    masked: str,
    body_open: int,
    body_close: int,
    type_name: str,
    base_name: str,
    indexer_param_count: int,
    event: bool,
) -> None:
    i = body_open + 1
    while i < body_close:
        i = _skip_space(masked, i, body_close)
        if i >= body_close:
            break
        start = i
        j = i
        paren = bracket = 0
        brace = arrow = semi = -1
        while j < body_close:
            ch = masked[j]
            if ch == "(":
                paren += 1
            elif ch == ")":
                paren = max(0, paren - 1)
            elif ch == "[":
                bracket += 1
            elif ch == "]":
                bracket = max(0, bracket - 1)
            elif paren == 0 and bracket == 0:
                if ch == "{":
                    brace = j
                    break
                if ch == "=" and j + 1 < body_close and masked[j + 1] == ">":
                    arrow = j
                    break
                if ch == ";":
                    semi = j
                    break
            j += 1

        if brace >= 0:
            close = _match_pair(masked, brace, "{", "}", body_close)
            end = body_close if close is None else close + 1
        elif arrow >= 0:
            end = _find_semicolon(masked, arrow + 2, body_close)
        elif semi >= 0:
            i = semi + 1  # auto/abstract accessor: no body, nothing to emit
            continue
        else:
            break

        kind = _accessor_kind(masked[start:j])
        if kind is not None:
            if event and kind not in {"add", "remove"}:
                i = end
                continue
            name = f"set_{base_name}" if kind == "init" else f"{kind}_{base_name}"
            _add_member(
                members,
                file,
                text,
                start,
                end,
                type_name,
                name,
                _accessor_params(kind, indexer_param_count),
            )
        i = end


def _extract_method(
    members: list[CSharpMember],
    file: str,
    text: str,
    masked: str,
    decl: dict,
    type_name: str,
    simple_type: str,
) -> None:
    start = decl["start"]
    header_end = decl["header_end"]
    attr_start = _skip_attributes(masked, start, header_end)
    signature = masked[attr_start:header_end]
    param_open = _find_param_open(signature)
    if param_open is None:
        return
    close = _match_pair(masked, attr_start + param_open, "(", ")", header_end)
    params_end = header_end if close is None else close
    param_count = _count_params(masked[attr_start + param_open + 1 : params_end])

    before = signature[:param_open].rstrip()
    if re.search(r"\boperator\b", before):
        name = _operator_name(before)
    elif "~" in before:
        name = "Finalize"
    else:
        stripped = _strip_generics(before).strip()
        name = stripped.rsplit(None, 1)[-1].rsplit(".", 1)[-1].strip().lstrip("@") if stripped else ""
        if name == simple_type:
            name = ".cctor" if re.search(r"\bstatic\b", stripped) else ".ctor"
    _add_member(members, file, text, start, decl["end"], type_name, name, param_count)


def _extract_property(
    members: list[CSharpMember],
    file: str,
    text: str,
    masked: str,
    decl: dict,
    type_name: str,
) -> None:
    start = decl["start"]
    header_end = decl["header_end"]
    attr_start = _skip_attributes(masked, start, header_end)
    header = masked[attr_start:header_end]
    base_name = _property_base_name(header)
    if not base_name:
        return

    indexer_param_count = 0
    this_match = re.search(r"\bthis\s*\[", header)
    if this_match is not None:
        bracket_open = attr_start + this_match.end() - 1
        bracket_close = _match_pair(masked, bracket_open, "[", "]", header_end)
        if bracket_close is not None:
            indexer_param_count = _count_params(masked[bracket_open + 1 : bracket_close])

    if decl["expr"]:
        name = f"get_{base_name}"
        _add_member(members, file, text, start, decl["end"], type_name, name, indexer_param_count)
        return

    _extract_accessors(
        members,
        file,
        text,
        masked,
        decl["body_open"],
        decl["body_close"],
        type_name,
        base_name,
        indexer_param_count,
        event=False,
    )


def _extract_event(
    members: list[CSharpMember],
    file: str,
    text: str,
    masked: str,
    decl: dict,
    type_name: str,
) -> None:
    attr_start = _skip_attributes(masked, decl["start"], decl["header_end"])
    base_name = _property_base_name(masked[attr_start:decl["header_end"]])
    if not base_name:
        return
    _extract_accessors(
        members,
        file,
        text,
        masked,
        decl["body_open"],
        decl["body_close"],
        type_name,
        base_name,
        0,
        event=True,
    )


def _extract_member(
    members: list[CSharpMember],
    file: str,
    text: str,
    masked: str,
    decl: dict,
    type_name: str,
    simple_type: str,
) -> None:
    if not decl["has_body"] and not decl["expr"]:
        return
    header_end = decl["header_end"]
    attr_start = _skip_attributes(masked, decl["start"], header_end)
    header = masked[attr_start:header_end]
    if re.search(r"\bevent\b", header):
        _extract_event(members, file, text, masked, decl, type_name)
    elif _find_param_open(header) is not None:
        _extract_method(members, file, text, masked, decl, type_name, simple_type)
    else:
        _extract_property(members, file, text, masked, decl, type_name)


# ---------------------------------------------------------------------------
# File walker
# ---------------------------------------------------------------------------


def _walk_scope(
    members: list[CSharpMember],
    file: str,
    text: str,
    masked: str,
    start: int,
    end: int,
    namespace: str,
    parent_type: str,
    in_type: bool,
) -> None:
    i = start
    while i < end:
        i = _skip_space(masked, i, end)
        if i >= end:
            break
        if masked[i] in ";}":
            i += 1
            continue
        if masked[i] == "#":
            # Preprocessor directive (#nullable, #region, ...): ignore the line itself.
            newline = masked.find("\n", i, end)
            i = end if newline < 0 else newline + 1
            continue
        decl = _scan_declaration(masked, i, end)
        decl_end = max(decl["end"], i + 1)
        decl["start"] = i
        header_end = decl["header_end"]
        keyword = _decl_keyword(masked, i, header_end)
        simple_type = _simple_type_name(masked, i, header_end, keyword) if keyword in _TYPE_KEYWORDS else ""

        if keyword == "namespace":
            name = _namespace_name(masked[i:header_end])
            if decl["has_body"]:
                _walk_scope(
                    members,
                    file,
                    text,
                    masked,
                    decl["body_open"] + 1,
                    decl["body_close"],
                    _combine_namespace(namespace, name),
                    "",
                    False,
                )
            else:
                namespace = _combine_namespace(namespace, name)
        elif keyword in _TYPE_KEYWORDS:
            if keyword not in {"enum", "delegate"} and decl["has_body"] and simple_type:
                if parent_type:
                    type_name = f"{parent_type}+{simple_type}"
                elif namespace:
                    type_name = f"{namespace}.{simple_type}"
                else:
                    type_name = simple_type
                _walk_scope(
                    members,
                    file,
                    text,
                    masked,
                    decl["body_open"] + 1,
                    decl["body_close"],
                    namespace,
                    type_name,
                    True,
                )
        elif in_type:
            _extract_member(
                members,
                file,
                text,
                masked,
                decl,
                parent_type,
                parent_type.rsplit("+", 1)[-1].rsplit(".", 1)[-1],
            )
        i = decl_end


def _split_file(file: str, text: str) -> list[CSharpMember]:
    masked = _mask_source(text)
    members: list[CSharpMember] = []
    _walk_scope(members, file, text, masked, 0, len(text), "", "", False)
    return members


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_ilspy_project(target: str, timeout: int) -> dict[str, str] | None:
    """Runs ``ilspycmd -p -o <tmpdir> <target>`` and returns ``{relative .cs path: text}``.

    Returns ``None`` when the tool fails.  The temporary directory is always removed.
    Files larger than 5 MB are skipped and reading stops after 50 MB in total.
    Never raises.
    """
    try:
        with tempfile.TemporaryDirectory(prefix="crowbar-ilspy-") as output_dir:
            proc = _run_tool(["ilspycmd", "-p", "-o", output_dir, target], timeout)
            if proc is None:
                return None

            files: dict[str, str] = {}
            total = 0
            for root, _dirs, names in os.walk(output_dir):
                for name in sorted(names):
                    if not name.lower().endswith(".cs"):
                        continue
                    full_path = os.path.join(root, name)
                    try:
                        size = os.path.getsize(full_path)
                    except OSError:
                        continue
                    if size > MAX_SOURCE_FILE_BYTES:
                        logger.warning("[dotnet_source] skipping %s: %d bytes exceeds the per-file limit", name, size)
                        continue
                    if total + size > MAX_TOTAL_SOURCE_BYTES:
                        logger.warning(
                            "[dotnet_source] stopping at %d bytes: the C# source limit is %d bytes",
                            total,
                            MAX_TOTAL_SOURCE_BYTES,
                        )
                        return files
                    try:
                        with open(full_path, encoding="utf-8", errors="replace") as handle:
                            content = handle.read()
                    except OSError as exc:
                        logger.warning("[dotnet_source] could not read %s: %s", full_path, exc)
                        continue
                    total += size
                    relative = os.path.relpath(full_path, output_dir).replace(os.sep, "/")
                    files[relative] = content
            return files
    except Exception as exc:  # noqa: BLE001 - the workflow must never crash
        logger.warning("[dotnet_source] ilspy project run failed: %s: %s", type(exc).__name__, exc)
        return None


def split_csharp_members(cs_files: dict[str, str]) -> list[CSharpMember]:
    """Splits ILSpy project output into members.  A file that fails to parse is skipped."""
    members: list[CSharpMember] = []
    for file, text in cs_files.items():
        if not isinstance(text, str):
            continue
        try:
            members.extend(_split_file(file, text))
        except Exception as exc:  # noqa: BLE001 - the workflow must never crash
            logger.warning("[dotnet_source] could not split %s: %s: %s", file, type(exc).__name__, exc)
    return members

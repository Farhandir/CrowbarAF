"""Deterministic, pure-Python static deobfuscation for script samples.

Nothing in the sample is executed or evaluated: every transform is a bounded
string/byte operation (base64, escaping, literals, XOR, zlib). The module is
defensive by design -- malformed or hostile input is skipped with a note and
never raises to the caller.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import heapq
import io
import logging
import re
import zlib
from collections import deque
from dataclasses import dataclass, field
from functools import lru_cache

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Hard limits (monkeypatch-friendly: always read at call time)
# --------------------------------------------------------------------------- #
MAX_LAYERS = 3
MAX_INPUT_CHARS = 12_000_000
MAX_DECODED_BYTES = 16 * 1024 * 1024
MAX_TOTAL_DECODED_BYTES = 32 * 1024 * 1024
MAX_BLOBS_PER_LAYER = 20
MIN_B64_LEN = 200
XOR_PROBE_BYTES = 4096

_MIN_B64_LINE = 60
_CONCAT_MAX_PASSES = 50


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class DecodedLayer:
    """One decoded/denormalised text layer."""

    text: str
    transform: str
    depth: int


@dataclass(frozen=True)
class EmbeddedBinary:
    """A PE/ZIP payload recovered from the script (never written to disk)."""

    kind: str
    sha256: str
    size: int
    transform: str


@dataclass(frozen=True)
class OpaqueBlob:
    """A base64 blob that decoded to bytes no transform could open (likely encrypted)."""

    sha256: str
    size: int
    transform: str


@dataclass
class DeobfResult:
    """All deterministic deobfuscation artefacts for one script."""

    layers: list[DecodedLayer] = field(default_factory=list)
    binaries: list[EmbeddedBinary] = field(default_factory=list)
    opaque: list[OpaqueBlob] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Classification:
    """Result of classifying decoded bytes."""

    kind: str  # "text" | "pe" | "zip" | "binary"
    text: str = ""
    payload: bytes = b""
    suffix: str = ""  # e.g. ">gzip", ">deflate", ">xor:0x5a"


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #
_COMMON_UNICODE_WS = frozenset(
    "\u00a0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000"
)

_STRING_LITERAL = r'"(?:[^"\\\r\n]|\\.)*"|\'(?:[^\'\\\r\n]|\\.)*\''

_INT_LITERAL = r"(?:0[xX][0-9A-Fa-f]+|&[Hh][0-9A-Fa-f]+|\d+)"


def _literal_body(literal: str) -> tuple[str, str]:
    """Returns ``(quote, raw_body)`` for a matched quoted literal."""
    if len(literal) < 2:
        return '"', literal
    return literal[0], literal[1:-1]


def _contains_unescaped(body: str, quote: str) -> bool:
    escaped = False
    for char in body:
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == quote:
            return True
    return False


def _escape_quote(body: str, quote: str) -> str:
    out: list[str] = []
    escaped = False
    for char in body:
        if escaped:
            out.append(char)
            escaped = False
            continue
        if char == "\\":
            out.append(char)
            escaped = True
            continue
        if char == quote:
            out.append("\\")
        out.append(char)
    return "".join(out)


def _join_literals(left: str, right: str) -> str:
    """Merges two quoted literals, keeping the result syntactically quoted."""
    left_quote, left_body = _literal_body(left)
    _, right_body = _literal_body(right)
    body = left_body + right_body
    quote = left_quote
    if _contains_unescaped(body, quote):
        other = "'" if quote == '"' else '"'
        if not _contains_unescaped(body, other):
            quote = other
        else:
            body = _escape_quote(body, quote)
    return quote + body + quote


def _quote_text(value: str) -> str:
    """Quotes a generated string with JS-style escapes."""
    out: list[str] = []
    for char in value:
        code = ord(char)
        if char == "\\":
            out.append("\\\\")
        elif char == '"':
            out.append('\\"')
        elif char == "\n":
            out.append("\\n")
        elif char == "\r":
            out.append("\\r")
        elif char == "\t":
            out.append("\\t")
        elif code < 32:
            out.append(f"\\x{code:02x}")
        else:
            out.append(char)
    return '"' + "".join(out) + '"'


def _parse_int_literal(value: str) -> int | None:
    """Parses decimal/``0x``/``&H`` integer literals within Unicode range."""
    text = value.strip()
    try:
        if text[:2].lower() == "0x":
            number = int(text[2:], 16)
        elif text[:2].lower() == "&h":
            number = int(text[2:], 16)
        else:
            number = int(text, 10)
    except ValueError:
        return None
    if 0 <= number <= 0x10FFFF:
        return number
    return None


# --------------------------------------------------------------------------- #
# Normalisation transforms (pure, bounded)
# --------------------------------------------------------------------------- #
def junk_strip(text: str) -> str:
    """Removes non-ASCII padding when more than 20% of the text is non-ASCII."""
    if not text:
        return text
    non_ascii = sum(1 for char in text if ord(char) > 127)
    if non_ascii <= len(text) * 0.20:
        return text
    cleaned = "".join(
        char for char in text if ord(char) < 128 or char in _COMMON_UNICODE_WS
    )
    return re.sub(r"(?:[ \t\r]*\n){2,}", "\n\n", cleaned)


_ESCAPE_RE = re.compile(
    r"\\x([0-9A-Fa-f]{2})|\\u([0-9A-Fa-f]{4})|%u([0-9A-Fa-f]{4})|%([0-9A-Fa-f]{2})"
)


def unescape(text: str) -> str:
    """Decodes ``\\xHH``, ``\\uHHHH``, ``%uHHHH`` and ``%HH`` escapes."""
    if not text or ("\\" not in text and "%" not in text):
        return text

    def replace(match: re.Match[str]) -> str:
        value = next(group for group in match.groups() if group is not None)
        try:
            return chr(int(value, 16))
        except (ValueError, OverflowError):
            return match.group(0)

    return _ESCAPE_RE.sub(replace, text)


_CONCAT_RE = re.compile(rf"({_STRING_LITERAL})\s*[+&]\s*({_STRING_LITERAL})")


def concat_fold(text: str) -> str:
    """Folds literal-to-literal string concatenations until a fixpoint."""
    if not text or ("+" not in text and "&" not in text):
        return text
    for _ in range(_CONCAT_MAX_PASSES):
        new_text = _CONCAT_RE.sub(lambda match: _join_literals(match.group(1), match.group(2)), text)
        if new_text == text:
            break
        text = new_text
    return text


_CHR_RE = re.compile(rf"\bChr(?:W|B)?\s*\(\s*({_INT_LITERAL})\s*\)", re.IGNORECASE)
_CHAR_CAST_RE = re.compile(rf"\[char\]\s*({_INT_LITERAL})", re.IGNORECASE)
_FROM_CHAR_CODE_RE = re.compile(r"\bString\s*\.\s*fromCharCode\s*\(([^()]*)\)", re.IGNORECASE)


def _replace_chr(match: re.Match[str]) -> str:
    number = _parse_int_literal(match.group(1))
    return match.group(0) if number is None else _quote_text(chr(number))


def _replace_char_cast(match: re.Match[str]) -> str:
    number = _parse_int_literal(match.group(1))
    return match.group(0) if number is None else _quote_text(chr(number))


def _replace_from_char_code(match: re.Match[str]) -> str:
    raw_args = [item.strip() for item in match.group(1).split(",")]
    if not raw_args or any(not item for item in raw_args):
        return match.group(0)
    numbers: list[int] = []
    for item in raw_args:
        if not re.fullmatch(_INT_LITERAL, item):
            return match.group(0)
        number = _parse_int_literal(item)
        if number is None:
            return match.group(0)
        numbers.append(number)
    return _quote_text("".join(chr(number) for number in numbers))


def charcodes(text: str) -> str:
    """Turns Chr()/ChrW()/ChrB(), [char]N and String.fromCharCode() into literals."""
    if not text:
        return text
    text = _FROM_CHAR_CODE_RE.sub(_replace_from_char_code, text)
    text = _CHR_RE.sub(_replace_chr, text)
    return _CHAR_CAST_RE.sub(_replace_char_cast, text)


_STRREVERSE_RE = re.compile(rf"\bStrReverse\s*\(\s*({_STRING_LITERAL})\s*\)", re.IGNORECASE)
_JS_REVERSE_RE = re.compile(
    rf"({_STRING_LITERAL})\s*\.\s*split\s*\(\s*(['\"])\s*\2\s*\)\s*\.\s*reverse\s*\(\s*\)"
    rf"\s*\.\s*join\s*\(\s*(['\"])\s*\3\s*\)",
    re.IGNORECASE,
)


def _replace_vbs_reverse(match: re.Match[str]) -> str:
    quote, body = _literal_body(match.group(1))
    return quote + body[::-1] + quote


def _replace_js_reverse(match: re.Match[str]) -> str:
    quote, body = _literal_body(match.group(1))
    return quote + body[::-1] + quote


def strreverse(text: str) -> str:
    """Resolves VBS ``StrReverse("x")`` and JS ``"x".split("").reverse().join("")``."""
    if not text:
        return text
    text = _STRREVERSE_RE.sub(_replace_vbs_reverse, text)
    return _JS_REVERSE_RE.sub(_replace_js_reverse, text)


def normalize_text(text: str) -> tuple[str, str]:
    """Applies the normalisation pipeline; returns ``(text, transform_chain)``."""
    if not text:
        return text, ""
    steps: tuple[tuple[str, object], ...] = (
        ("junk-strip", junk_strip),
        ("unescape", unescape),
        ("concat-fold", concat_fold),
        ("charcodes", charcodes),
        ("concat-fold", concat_fold),
        ("strreverse", strreverse),
    )
    chain: list[str] = []
    current = text
    for name, func in steps:
        try:
            new_text = func(current)  # type: ignore[operator]
        except Exception as exc:  # noqa: BLE001 - a failed transform must not stop analysis
            logger.debug("[script_deobf] transform %s failed: %s", name, exc)
            continue
        if new_text != current:
            if not chain or chain[-1] != name:
                chain.append(name)
            current = new_text
    return current, ">".join(chain)


# --------------------------------------------------------------------------- #
# Base64 candidate extraction / decoding
# --------------------------------------------------------------------------- #
@lru_cache(maxsize=8)
def _b64_run_re(min_length: int) -> re.Pattern[str]:
    return re.compile(rf"[A-Za-z0-9+/]{{{min_length},}}={{0,2}}")


_B64_LINE_STRIP_RE = re.compile(r"[\s\"'`+&,;]")
_B64_LINE_RE = re.compile(r"[A-Za-z0-9+/]+")
_STRING_LITERAL_RE = re.compile(_STRING_LITERAL)
# Assignment prefix of a chunk line: ``$s += '...'``, ``s = s + "..."``,
# ``Dim s: s = "..."``. Anchored and free of nested quantifiers (linear-time).
_ASSIGN_PREFIX_RE = re.compile(
    r"^\s*(?:(?:var|let|const|dim)\s+)?[\$\w.\[\]]+\s*(?::\s*[\$\w.\[\]]+\s*)?(?:\+=|&=|=)\s*",
    re.IGNORECASE,
)
_PS_ENCODED_RE = re.compile(
    r"(?<![\w-])-e(?:nc(?:odedcommand)?)?\s+[\"']?([A-Za-z0-9+/=]{20,})",
    re.IGNORECASE,
)


def _line_chunk_candidate(line: str) -> str | None:
    """Returns the payload slice of one line for the line-chunk join.

    Payloads are usually split as ``$s += '...'`` / ``s = s + "..."`` so the
    assignment prefix hides the chunk from a plain base64 fullmatch. For such
    assignment lines only the quoted literals are kept (concatenated). ``None``
    means the line had no assignment/literal and must use the legacy strip.
    """
    if "=" not in line or not _ASSIGN_PREFIX_RE.match(line):
        return None
    literals = _STRING_LITERAL_RE.findall(line)
    if not literals:
        return None
    return "".join(_literal_body(literal)[1] for literal in literals)


def _iter_base64_candidates(text: str):
    """Yields raw base64 candidate strings from runs, line chunks and -EncodedCommand."""
    if not text:
        return
    min_len = max(1, MIN_B64_LEN)
    for match in _b64_run_re(min_len).finditer(text):
        yield match.group(0), "run"

    chunks: list[str] = []
    for line in io.StringIO(text):
        candidate = _line_chunk_candidate(line)
        if candidate is None:
            candidate = _B64_LINE_STRIP_RE.sub("", line)
        cleaned = candidate.rstrip("=")
        if len(cleaned) >= _MIN_B64_LINE and _B64_LINE_RE.fullmatch(cleaned):
            chunks.append(cleaned)
            continue
        if not line.strip() and chunks:
            continue  # blank lines inside a sequence must not break the join
        if chunks:
            joined = "".join(chunks)
            if len(joined) >= _MIN_B64_LINE:
                yield joined, "lines"
            chunks = []
    if chunks:
        joined = "".join(chunks)
        if len(joined) >= _MIN_B64_LINE:
            yield joined, "lines"

    for match in _PS_ENCODED_RE.finditer(text):
        yield match.group(1), "ps"


def _select_base64_candidates(text: str) -> list[tuple[str, str]]:
    """Returns the largest unique candidates, capped at ``MAX_BLOBS_PER_LAYER``."""
    limit = max(0, MAX_BLOBS_PER_LAYER)
    if limit == 0:
        return []
    heap: list[tuple[int, int, str, str]] = []
    seen: set[str] = set()
    sequence = 0
    for payload, origin in _iter_base64_candidates(text):
        payload = payload.strip()
        if not payload or payload in seen:
            continue
        seen.add(payload)
        sequence += 1
        entry = (len(payload), -sequence, payload, origin)
        if len(heap) < limit:
            heapq.heappush(heap, entry)
        elif entry[0] > heap[0][0]:
            heapq.heapreplace(heap, entry)
    selected = sorted(heap, key=lambda item: (-item[0], -item[1]))
    return [(item[2], item[3]) for item in selected]


def _pad_b64(core: str) -> str:
    if len(core) % 4 == 1:
        core = core[:-1]
    return core + "=" * ((-len(core)) % 4)


def _decode_b64_variant(core: str) -> bytes | None:
    try:
        return base64.b64decode(_pad_b64(core), validate=True)
    except (binascii.Error, ValueError):
        return None


def _printable_ratio(data: bytes, limit: int = 4000) -> float:
    sample = data[:limit]
    if not sample:
        return 0.0
    printable = sum(1 for byte in sample if 32 <= byte < 127 or byte in (9, 10, 13))
    return printable / len(sample)


def _looks_like_pe(data: bytes) -> bool:
    if not data.startswith(b"MZ"):
        return False
    head = data[:1024]
    return b"This program" in head or b"PE\x00\x00" in head


def _probe_is_plausible(data: bytes) -> bool:
    """Cheap plausibility probe used to prefer the plain or reversed base64 variant."""
    if not data:
        return False
    if _looks_like_pe(data) or data.startswith(b"\x1f\x8b") or data.startswith(b"PK\x03\x04"):
        return True
    sample = data[:400]
    if len(sample) >= 4:
        odd = sample[1::2]
        zeros = sum(1 for byte in odd if byte == 0)
        if odd and zeros / len(odd) >= 0.6:
            return True
    return _printable_ratio(data) >= 0.90


def _choose_b64_bytes(payload: str) -> bytes | None:
    """Decodes plain or reversed base64, preferring the first plausible payload."""
    core = "".join(payload.split()).rstrip("=")
    if not core:
        return None
    variants: list[tuple[str, bytes]] = []
    for label, candidate in (("plain", core), ("reversed", core[::-1])):
        raw = _decode_b64_variant(candidate)
        if raw is not None:
            variants.append((label, raw))
    if not variants:
        return None
    for _label, raw in variants:
        if _probe_is_plausible(raw):
            return raw
    return variants[0][1]


# --------------------------------------------------------------------------- #
# Payload classification
# --------------------------------------------------------------------------- #
def _is_utf16le_text(data: bytes) -> bool:
    sample = data[:400]
    if len(sample) < 4:
        return False
    odd = sample[1::2]
    if not odd:
        return False
    zeros = sum(1 for byte in odd if byte == 0)
    if zeros / len(odd) < 0.6:
        return False
    even = sample[0::2]
    textish = sum(1 for byte in even if byte == 0 or 32 <= byte < 127 or byte in (9, 10, 13))
    return textish / len(even) >= 0.8


def _as_text(data: bytes) -> str | None:
    if _is_utf16le_text(data):
        return data.decode("utf-16-le", errors="replace").lstrip("\ufeff")
    if _printable_ratio(data) >= 0.90:
        return data.decode("utf-8", errors="replace")
    return None


def _decode_limit(budget: _Budget | None) -> int:
    limit = MAX_DECODED_BYTES
    if budget is not None:
        limit = min(limit, max(0, budget.remaining))
    return limit


def _try_gzip(data: bytes, budget: _Budget | None) -> bytes | None:
    limit = _decode_limit(budget)
    if limit <= 0:
        return None
    try:
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        output = decompressor.decompress(data, limit)
    except zlib.error:
        return None
    if not output:
        return None
    if budget is not None and not budget.take(len(output)):
        return None
    return output


def _try_raw_deflate(data: bytes, budget: _Budget | None) -> bytes | None:
    limit = _decode_limit(budget)
    if limit <= 0:
        return None
    try:
        decompressor = zlib.decompressobj(-15)
        output = decompressor.decompress(data, limit)
    except zlib.error:
        return None
    if not output:
        return None
    if budget is not None and not budget.take(len(output)):
        return None
    return output


def _find_xor_key(data: bytes) -> int | None:
    probe = data[:XOR_PROBE_BYTES]
    if not probe:
        return None
    for key in range(1, 256):
        table = bytes(byte ^ key for byte in range(256))
        decoded = probe.translate(table)
        if _looks_like_pe(decoded) or decoded.startswith(b"\x1f\x8b"):
            return key
        if _printable_ratio(decoded, limit=len(decoded)) >= 0.95:
            return key
    return None


def _classify_bytes(
    data: bytes,
    budget: _Budget | None,
    *,
    allow_xor: bool = True,
    round_number: int = 0,
) -> Classification:
    if not data:
        return Classification("binary")

    if _looks_like_pe(data):
        return Classification("pe", payload=data)

    if data.startswith(b"\x1f\x8b") and round_number < MAX_LAYERS:
        inflated = _try_gzip(data, budget)
        if inflated is not None:
            nested = _classify_bytes(
                inflated, budget, allow_xor=allow_xor, round_number=round_number + 1
            )
            return Classification(nested.kind, nested.text, nested.payload, ">gzip" + nested.suffix)

    if data.startswith(b"PK\x03\x04"):
        return Classification("zip", payload=data)

    text = _as_text(data)
    if text is not None:
        return Classification("text", text=text, payload=data)

    if round_number < MAX_LAYERS:
        inflated = _try_raw_deflate(data, budget)
        if inflated is not None:
            nested = _classify_bytes(
                inflated, budget, allow_xor=allow_xor, round_number=round_number + 1
            )
            return Classification(
                nested.kind, nested.text, nested.payload, ">deflate" + nested.suffix
            )

    if allow_xor and round_number < MAX_LAYERS:
        key = _find_xor_key(data)
        if key is not None:
            table = bytes(byte ^ key for byte in range(256))
            decoded = data.translate(table)
            nested = _classify_bytes(
                decoded, budget, allow_xor=False, round_number=round_number + 1
            )
            return Classification(
                nested.kind, nested.text, nested.payload, nested.suffix + f">xor:0x{key:02x}"
            )

    return Classification("binary", payload=data)


def classify_bytes(data: bytes) -> Classification:
    """Classifies decoded bytes as text/PE/ZIP/binary (also gunzips and de-XORs)."""
    try:
        if not isinstance(data, (bytes, bytearray)):
            return Classification("binary")
        return _classify_bytes(bytes(data), None)
    except Exception as exc:  # noqa: BLE001 - classification must never raise
        logger.warning("[script_deobf] classification failed: %s", exc)
        return Classification("binary")


# --------------------------------------------------------------------------- #
# Deobfuscation orchestration
# --------------------------------------------------------------------------- #
@dataclass
class _Budget:
    remaining: int
    notes: list[str]

    def take(self, amount: int) -> bool:
        if amount < 0 or amount > self.remaining:
            return False
        self.remaining -= amount
        return True


class _Context:
    def __init__(self, result: DeobfResult) -> None:
        self.result = result
        self.queue: deque[tuple[str, int]] = deque()
        self.budget = _Budget(MAX_TOTAL_DECODED_BYTES, result.notes)
        self._seen_layers: set[str] = set()
        self._seen_binaries: set[tuple[str, str, str]] = set()
        self._seen_opaque: set[str] = set()

    def add_layer(self, text: str, transform: str, depth: int) -> bool:
        if not text or not 1 <= depth <= MAX_LAYERS:
            return False
        digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
        if digest in self._seen_layers:
            return False
        self._seen_layers.add(digest)
        self.result.layers.append(DecodedLayer(text=text, transform=transform, depth=depth))
        self.queue.append((text, depth))
        return True

    def add_binary(self, kind: str, payload: bytes, transform: str) -> None:
        digest = hashlib.sha256(payload).hexdigest()
        key = (kind, digest, transform)
        if key in self._seen_binaries:
            return
        self._seen_binaries.add(key)
        self.result.binaries.append(
            EmbeddedBinary(kind=kind, sha256=digest, size=len(payload), transform=transform)
        )

    def add_opaque(self, payload: bytes, transform: str) -> None:
        # The same blob is often found twice (as a plain run and as a line-chunk join).
        digest = hashlib.sha256(payload).hexdigest()
        if digest in self._seen_opaque:
            return
        self._seen_opaque.add(digest)
        self.result.opaque.append(OpaqueBlob(sha256=digest, size=len(payload), transform=transform))
        self.result.notes.append(f"undecodable/possibly encrypted binary ({len(payload)} bytes)")

    def consume_base64(self, payload: str, depth: int) -> None:
        core = "".join(payload.split()).rstrip("=")
        if not core:
            return
        estimated = (len(core) * 3) // 4
        if estimated > MAX_DECODED_BYTES:
            self.result.notes.append(
                f"base64 blob {len(core)} B: exceeds per-blob decode limit"
            )
            return
        if estimated > self.budget.remaining:
            self.result.notes.append(
                f"base64 blob {len(core)} B: exceeds total decode budget"
            )
            return
        raw = _choose_b64_bytes(payload)
        if raw is None:
            self.result.notes.append(f"base64 blob {len(core)} B: undecodable/encrypted")
            return
        if not self.budget.take(len(raw)):
            self.result.notes.append(
                f"base64 blob {len(raw)} B: exceeds total decode budget"
            )
            return
        try:
            classified = _classify_bytes(raw, self.budget)
        except Exception as exc:  # noqa: BLE001 - one bad blob must not abort the file
            logger.debug("[script_deobf] classification skipped: %s", exc)
            return
        transform = f"base64{classified.suffix}"
        if classified.kind in ("pe", "zip"):
            self.add_binary(classified.kind, classified.payload, transform)
        elif classified.kind == "text":
            self.add_layer(classified.text, transform, depth)
        else:
            self.add_opaque(raw, transform)


def deobfuscate(text: str) -> DeobfResult:
    """Runs bounded static deobfuscation over script text.

    Never raises: failures are logged and represented in ``result.notes``.
    """
    result = DeobfResult()
    try:
        if not isinstance(text, str) or not text:
            return result
        if len(text) > MAX_INPUT_CHARS:
            result.notes.append(
                f"input {len(text)} chars exceeds limit; truncated to {MAX_INPUT_CHARS}"
            )
            text = text[:MAX_INPUT_CHARS]

        context = _Context(result)
        context.queue.append((text, 0))
        while context.queue:
            current, depth = context.queue.popleft()
            if depth >= MAX_LAYERS:
                continue
            normalized, chain = normalize_text(current)
            if chain and normalized != current:
                context.add_layer(normalized, chain, depth + 1)
            for payload, _origin in _select_base64_candidates(current):
                context.consume_base64(payload, depth + 1)
    except Exception as exc:  # noqa: BLE001 - deobfuscation must never crash the caller
        logger.warning("[script_deobf] deobfuscation aborted: %s", exc)
        result.notes.append(f"deobfuscation aborted: {exc}")
    return result

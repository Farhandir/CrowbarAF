"""Deterministic static script deobfuscation: transforms, decoding and caps.

Every payload here is harmless synthetic text (example.com / RFC 5737 IPs) and
the only "PE" is a fake buffer built from MZ + padding + the DOS stub string.
"""

from __future__ import annotations

import base64
import gzip
import time

import analyzers.script_deobf as deobf
from analyzers.script import extract_script_iocs
from analyzers.script_deobf import (
    MAX_LAYERS,
    charcodes,
    classify_bytes,
    concat_fold,
    deobfuscate,
    junk_strip,
    normalize_text,
    strreverse,
    unescape,
)

URL = "http://example.com/x"
FILLER = "Harmless note about example.com. "


def _b64(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode()
    return base64.b64encode(data).decode("ascii")


def _fake_pe() -> bytes:
    return b"MZ" + b"\x90" * 200 + b"This program cannot be run in DOS mode"


def _line_chunks(payload: str | bytes, width: int = 60) -> list[str]:
    """Base64-encodes ``payload`` into exact ``width``-char line chunks."""
    raw = payload.encode() if isinstance(payload, str) else bytes(payload)
    while len(raw) % 45:  # 45 input bytes == exactly 60 base64 chars, no padding
        raw += b" "
    blob = _b64(raw)
    return [blob[index:index + width] for index in range(0, len(blob), width)]


# --------------------------------------------------------------------------- #
# Text normalisation transforms
# --------------------------------------------------------------------------- #
def test_junk_strip_reveals_ascii_script_and_removes_cjk_padding():
    text = "脚" * 20 + 'CreateObject("WScript.Shell")'
    assert junk_strip(text) == 'CreateObject("WScript.Shell")'


def test_junk_strip_keeps_plain_ascii_untouched():
    text = 'WScript.Echo "hello"\n\n\nnext line\n'
    assert junk_strip(text) == text


def test_unescape_decodes_js_and_percent_escapes():
    assert unescape(r"\x57\x53") == "WS"
    assert unescape(r"\u0057") == "W"
    assert unescape("%u0057") == "W"
    assert unescape("%57") == "W"


def test_concat_fold_js_vbs_and_powershell_literals():
    assert concat_fold('"WSc" + "ript"') == '"WScript"'
    assert concat_fold("'WSc' & 'ript'") == "'WScript'"
    assert concat_fold('"WSc" +\n    "ript"') == '"WScript"'


def test_concat_fold_never_touches_variables():
    assert concat_fold('"a" + b') == '"a" + b'
    assert concat_fold('"a" & b') == '"a" & b'


def test_charcodes_vbs_string_fromcharcode_and_powershell_cast():
    folded = concat_fold(charcodes('Chr(87) & Chr(83) & "cript.Shell"'))
    assert folded == '"WScript.Shell"'
    assert charcodes("String.fromCharCode(104,116,116,112)") == '"http"'
    assert charcodes("[char]0x41") == '"A"'
    assert charcodes("ChrW(&H41)") == '"A"'
    assert charcodes("Chr(65)") == '"A"'


def test_strreverse_vbs_and_js_forms():
    assert strreverse('StrReverse("abc")') == '"cba"'
    assert strreverse('"abc".split("").reverse().join("")') == '"cba"'


def test_normalize_text_produces_single_chain():
    text = "脚" * 20 + 'Set sh = CreateObject(Chr(87) & Chr(83) & "cript.Shell")'
    normalized, chain = normalize_text(text)
    assert normalized == 'Set sh = CreateObject("WScript.Shell")'
    assert chain == "junk-strip>charcodes>concat-fold"


def test_deobfuscate_normalized_layer_uses_chain():
    text = "脚" * 20 + 'Set sh = CreateObject(Chr(87) & Chr(83) & "cript.Shell")'
    result = deobfuscate(text)
    assert len(result.layers) == 1
    layer = result.layers[0]
    assert layer.depth == 1
    assert layer.transform == "junk-strip>charcodes>concat-fold"
    assert '"WScript.Shell"' in layer.text


# --------------------------------------------------------------------------- #
# Base64 extraction and decoding
# --------------------------------------------------------------------------- #
def test_base64_plain_blob_yields_text_layer_and_url():
    payload = _b64(FILLER * 10 + URL)
    result = deobfuscate(f'$payload = "{payload}";')
    matching = [layer for layer in result.layers if URL in layer.text]
    assert matching, result.layers
    assert matching[0].depth == 1
    assert matching[0].transform == "base64"
    assert URL in extract_script_iocs(matching[0].text)["url"]


def test_base64_line_chunked_blob_with_continuations():
    raw = (FILLER * 10 + URL).encode()
    while len(raw) % 45:  # 45 input bytes == exactly 60 base64 chars
        raw += b" "
    blob = _b64(raw)
    chunks = [blob[index:index + 60] for index in range(0, len(blob), 60)]
    assert len(chunks) >= 4 and all(len(chunk) == 60 for chunk in chunks)
    source = "\n".join(f'  "{chunk}" +' for chunk in chunks)

    result = deobfuscate(source)

    matching = [layer for layer in result.layers if URL in layer.text]
    assert matching, result.layers
    assert extract_script_iocs(matching[0].text)["url"] == [URL]


def test_powershell_incremental_line_chunks_are_joined():
    chunks = _line_chunks(FILLER * 80 + URL)
    assert len(chunks) > 50
    lines = [f"$s = '{chunks[0]}'"]
    for index, chunk in enumerate(chunks[1:], start=1):
        lines.append(f"$s += '{chunk}'")
        if index == 10:
            lines.append("")  # blank lines inside the sequence must not break the join

    result = deobfuscate("\n".join(lines))

    matching = [layer for layer in result.layers if URL in layer.text]
    assert matching, result.layers
    assert matching[0].transform == "base64"


def test_javascript_assignment_and_concat_line_chunks_are_joined():
    chunks = _line_chunks(FILLER * 10 + URL)
    assert len(chunks) >= 8
    sources = [
        "\n".join([f'var s = "{chunks[0]}";'] + [f's = s + "{chunk}";' for chunk in chunks[1:]]),
        "\n".join([f'var s = "{chunks[0]}";'] + [f's += "{chunk}";' for chunk in chunks[1:]]),
        "\n".join([f'var s = "{chunks[0]}";'] + [f's = s.concat("{chunk}");' for chunk in chunks[1:]]),
    ]
    for source in sources:
        result = deobfuscate(source)
        assert any(URL in layer.text for layer in result.layers), (source, result.layers)


def test_vbs_ampersand_line_chunks_are_joined():
    chunks = _line_chunks(FILLER * 10 + URL)
    source = "\n".join([f'Dim s: s = "{chunks[0]}"'] + [f's = s & "{chunk}"' for chunk in chunks[1:]])

    result = deobfuscate(source)

    assert any(URL in layer.text for layer in result.layers)


def test_random_line_chunks_are_seen_and_reported_as_undecodable():
    chunks = _line_chunks(bytes(range(1, 256)) * 2)
    source = "\n".join([f"$s = '{chunks[0]}'"] + [f"$s += '{chunk}'" for chunk in chunks[1:]])

    result = deobfuscate(source)

    assert result.layers == []
    assert any("undecodable/possibly encrypted" in note for note in result.notes), result.notes


def test_plain_powershell_script_creates_no_base64_candidates():
    script = "\n".join(
        [
            '$applicationConfigurationPath = "C:\\Program Files\\Example Corporation\\Sample Application"',
            '$applicationLogDirectoryPath = "C:\\ProgramData\\Example Corporation\\logs"',
            '$remoteServiceEndpointAddress = "https://example.com/service/endpoint"',
            'Write-Host "Starting the harmless example application"',
            'if ($applicationConfigurationPath) {',
            '    $applicationLogDirectoryPath = Join-Path $applicationLogDirectoryPath "application.log"',
            "}",
        ]
    )

    assert deobf._select_base64_candidates(script) == []


def test_base64_reversed_blob_is_decoded():
    blob = _b64(FILLER * 10 + URL)
    result = deobfuscate(blob[::-1])
    assert any(URL in layer.text for layer in result.layers)


def test_powershell_encoded_command_uses_utf16le():
    script = "Write-Host '" + URL + "'; " + FILLER * 10
    payload = _b64(script.encode("utf-16-le"))
    result = deobfuscate(f"powershell.exe -NoProfile -EncodedCommand {payload}")
    matching = [layer for layer in result.layers if URL in layer.text]
    assert matching, result.layers
    assert matching[0].transform == "base64"


def test_base64_len_mod_four_one_drops_last_char():
    raw = (FILLER * 10 + URL).encode()
    while len(raw) % 3:  # no "=" padding, so appending one char leaves len % 4 == 1
        raw += b" "
    blob = _b64(raw)
    assert "=" not in blob
    result = deobfuscate(blob + "A")
    assert any(URL in layer.text for layer in result.layers)


def test_identical_base64_blobs_are_deduplicated():
    blob = _b64(FILLER * 10 + URL)
    result = deobfuscate(f'var a = "{blob}";\nvar b = "{blob}";\n')
    assert sum(URL in layer.text for layer in result.layers) == 1


# --------------------------------------------------------------------------- #
# Nested layers
# --------------------------------------------------------------------------- #
def test_nested_base64_url_found_at_depth_two():
    inner = FILLER * 10 + URL
    middle = FILLER * 4 + _b64(inner)
    outer = _b64(middle)
    result = deobfuscate(outer)

    matching = [layer for layer in result.layers if URL in layer.text]
    assert matching, result.layers
    assert matching[0].depth == 2
    assert matching[0].transform == "base64"


def test_depth_beyond_max_layers_is_not_followed():
    payload = URL
    for _ in range(5):
        payload = _b64((FILLER * 6) + payload)

    result = deobfuscate(payload)

    assert max(layer.depth for layer in result.layers) <= MAX_LAYERS
    assert all(URL not in layer.text for layer in result.layers)


# --------------------------------------------------------------------------- #
# Compressed / XOR payloads
# --------------------------------------------------------------------------- #
def test_gzip_payload_is_decompressed():
    blob = _b64(gzip.compress((FILLER * 10 + URL).encode()))
    result = deobfuscate(blob)
    matching = [layer for layer in result.layers if URL in layer.text]
    assert matching, result.layers
    assert matching[0].transform == "base64>gzip"


def test_xor_pe_payload_is_detected_with_key_in_transform():
    xored = bytes(byte ^ 0x5A for byte in _fake_pe())
    blob = _b64(xored)
    result = deobfuscate(blob)

    assert len(result.binaries) == 1
    binary = result.binaries[0]
    assert binary.kind == "pe"
    assert binary.transform == "base64>xor:0x5a"
    assert binary.size == len(_fake_pe())
    assert len(binary.sha256) == 64


def test_random_binary_payload_records_note_without_binaries():
    blob = _b64(bytes(range(1, 256)) * 2)
    result = deobfuscate(blob)

    assert result.binaries == []
    assert result.notes
    assert any("binary" in note for note in result.notes)


def test_classify_bytes_signatures():
    assert classify_bytes(_fake_pe()).kind == "pe"
    assert classify_bytes(b"PK\x03\x04" + b"\x00" * 32).kind == "zip"
    assert classify_bytes(b"plain harmless text\n").kind == "text"
    assert classify_bytes(bytes(range(1, 256)) * 2).kind == "binary"
    gzipped = classify_bytes(gzip.compress(b"harmless text"))
    assert gzipped.kind == "text"
    assert gzipped.suffix == ">gzip"


# --------------------------------------------------------------------------- #
# Bounded execution
# --------------------------------------------------------------------------- #
def test_large_base64_alphabet_string_is_bounded(monkeypatch):
    monkeypatch.setattr(deobf, "MAX_TOTAL_DECODED_BYTES", 1024)
    monkeypatch.setattr(deobf, "MAX_DECODED_BYTES", 1024)

    started = time.perf_counter()
    result = deobfuscate("A" * 9_000_000)
    elapsed = time.perf_counter() - started

    assert elapsed < 5.0
    assert result.layers == []
    assert result.binaries == []
    assert result.notes


def test_per_blob_decode_cap_is_enforced(monkeypatch):
    monkeypatch.setattr(deobf, "MAX_DECODED_BYTES", 32)
    monkeypatch.setattr(deobf, "MAX_TOTAL_DECODED_BYTES", 1024)

    result = deobfuscate(_b64("A" * 200))

    assert result.layers == []
    assert result.binaries == []
    assert any("per-blob" in note for note in result.notes)


def test_deobfuscate_never_raises_on_garbage():
    result = deobfuscate("\x00\x01%zz\\q" * 1000)
    assert result.layers == []
    assert result.binaries == []

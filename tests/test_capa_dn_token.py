from analyzers.capa_floss import _parse_capa_address, extract_ghidra_hints


def test_parse_absolute_forms_unchanged():
    assert _parse_capa_address({"type": "absolute", "value": 4198400}) == 4198400
    assert _parse_capa_address(["absolute", 4198400]) == 4198400
    assert _parse_capa_address("0x401000") == 0x401000
    assert _parse_capa_address(4198400) == 4198400


def test_parse_dn_token_forms():
    assert _parse_capa_address({"type": "dn token", "value": 0x06000012}) == 0x06000012
    assert _parse_capa_address({"type": "dn token offset", "value": [0x06000012, 7]}) == 0x06000012
    assert _parse_capa_address(["dn token", 0x06000003]) == 0x06000003


def test_parse_non_addresses_rejected():
    assert _parse_capa_address({"type": "file"}) is None
    assert _parse_capa_address({"type": "no address"}) is None
    assert _parse_capa_address({"type": "relative", "value": 16}) is None
    assert _parse_capa_address({"type": "dn token offset", "value": []}) is None
    assert _parse_capa_address(["absolute", 1, 2]) is None


def test_dotnet_hints_use_token_hex_as_offset():
    report = {"rules": {"download URL": {
        "meta": {"scopes": {"static": "function"}},
        "matches": [[{"type": "dn token", "value": 0x06000012}, {}]],
    }}}
    assert extract_ghidra_hints(report) == [{"offset": "0x6000012", "rule": "download URL"}]

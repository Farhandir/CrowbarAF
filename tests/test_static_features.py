"""pefile yardımcıları, findings üretimi ve static_feature_node için birim testleri."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import nodes
from nodes import (
    build_findings,
    extract_imports,
    match_import_combos,
    merge_findings,
    section_entropy,
    static_feature_node,
)
from state import AgentState, Finding


# --------------------------------------------------------------------------- #
# pefile sahte nesneleri (gerçek PE dosyası gerektirmeden)
# --------------------------------------------------------------------------- #
class _FakePEFormatError(Exception):
    pass


class _FakePE:
    def __init__(self, sections=(), imports=()):
        self.sections = [
            SimpleNamespace(Name=name.encode().ljust(8, b"\x00"), get_entropy=lambda e=ent: e)
            for name, ent in sections
        ]
        self.DIRECTORY_ENTRY_IMPORT = [
            SimpleNamespace(imports=[SimpleNamespace(name=n.encode() if n else None) for n in names])
            for names in imports
        ]
        self.closed = False

    def parse_data_directories(self, directories=None):
        pass

    def close(self):
        self.closed = True


def _install_fake_pefile(monkeypatch, pe=None, error=None):
    def factory(path, fast_load=False):
        if error is not None:
            raise error
        return pe

    fake = SimpleNamespace(
        PE=factory,
        PEFormatError=_FakePEFormatError,
        DIRECTORY_ENTRY={"IMAGE_DIRECTORY_ENTRY_IMPORT": 1},
    )
    monkeypatch.setattr(nodes, "pefile", fake)
    return fake


class TestExtractImports:
    def test_collects_unique_names_and_skips_ordinals(self, monkeypatch) -> None:
        pe = _FakePE(imports=[["VirtualAlloc", None, "CreateFileA"], ["VirtualAlloc", "ExitProcess"]])
        _install_fake_pefile(monkeypatch, pe)
        assert extract_imports("x.exe") == ["VirtualAlloc", "CreateFileA", "ExitProcess"]
        assert pe.closed

    def test_invalid_pe_returns_empty(self, monkeypatch) -> None:
        _install_fake_pefile(monkeypatch, error=_FakePEFormatError("bad"))
        assert extract_imports("x") == []

    def test_unexpected_error_returns_empty(self, monkeypatch) -> None:
        _install_fake_pefile(monkeypatch, error=PermissionError("denied"))
        assert extract_imports("x") == []

    def test_pefile_not_installed(self, monkeypatch) -> None:
        monkeypatch.setattr(nodes, "pefile", None)
        assert extract_imports("x") == []

    def test_real_pefile_on_non_pe_file(self, tmp_path) -> None:
        pytest.importorskip("pefile")
        path = tmp_path / "a.txt"
        path.write_text("not a pe")
        assert extract_imports(str(path)) == []

    def test_missing_file_returns_empty(self, tmp_path) -> None:
        assert extract_imports(str(tmp_path / "yok.exe")) == []


class TestSectionEntropy:
    def test_names_and_values(self, monkeypatch) -> None:
        pe = _FakePE(sections=[(".text", 6.1), (".rsrc", 7.8), (".text", 5.0)])
        _install_fake_pefile(monkeypatch, pe)
        assert section_entropy("x.exe") == {".text": 6.1, ".rsrc": 7.8, ".text#2": 5.0}
        assert pe.closed

    def test_invalid_pe_returns_empty(self, monkeypatch) -> None:
        _install_fake_pefile(monkeypatch, error=_FakePEFormatError("bad"))
        assert section_entropy("x") == {}

    def test_real_pefile_on_non_pe_file(self, tmp_path) -> None:
        pytest.importorskip("pefile")
        path = tmp_path / "a.bin"
        path.write_bytes(b"\x00" * 64)
        assert section_entropy(str(path)) == {}

    def test_pefile_not_installed(self, monkeypatch) -> None:
        monkeypatch.setattr(nodes, "pefile", None)
        assert section_entropy("x") == {}


class TestMatchImportCombos:
    def test_process_injection(self) -> None:
        imports = ["virtualalloc", "WRITEPROCESSMEMORY", "CreateRemoteThread", "Sleep"]
        assert match_import_combos(imports) == ["Process Injection Combo"]

    def test_ex_variants_count(self) -> None:
        assert match_import_combos(["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThreadEx"]) == [
            "Process Injection Combo"
        ]

    @pytest.mark.parametrize(
        "imports",
        [[], ["VirtualAlloc", "WriteProcessMemory"], ["WriteProcessMemory", "CreateRemoteThread"], ["Sleep"]],
    )
    def test_incomplete_combo_does_not_match(self, imports: list[str]) -> None:
        assert match_import_combos(imports) == []

    def test_ignores_non_strings(self) -> None:
        assert match_import_combos([None, 5]) == []  # type: ignore[list-item]


# --------------------------------------------------------------------------- #
# build_findings / merge_findings
# --------------------------------------------------------------------------- #
def _build(**overrides):
    args = dict(
        yara_results=[],
        capabilities={},
        ghidra_hints=[],
        import_combos=[],
        entropy={},
        ioc_strings=[],
    )
    args.update(overrides)
    return build_findings(**args)


class TestBuildFindings:
    def test_empty(self) -> None:
        assert _build() == []

    def test_yara(self) -> None:
        out = _build(yara_results=[{"rule": "Emotet", "tags": [], "meta": {}}, {"no_rule": 1}, "x"])
        assert out == [Finding(source="yara", kind="rule", value="Emotet")]

    def test_capa_rules_attack_behavior_and_addresses(self) -> None:
        caps = {
            "matched_rules": ["encrypt data using AES", "is packed"],
            "mitre_attack": ["T1055 - Process Injection (Defense Evasion)"],
            "malware_behavior": ["B0001 - Debugger Detection"],
        }
        hints = [{"offset": "0x401000", "rule": "encrypt data using AES"}]
        out = _build(capabilities=caps, ghidra_hints=hints)
        assert out == [
            Finding(source="capa", kind="rule", value="encrypt data using AES", address="0x401000"),
            Finding(source="capa", kind="rule", value="is packed"),  # adres yok -> genel
            Finding(source="capa", kind="attack", value="T1055 - Process Injection (Defense Evasion)"),
            Finding(source="capa", kind="behavior", value="B0001 - Debugger Detection"),
        ]

    def test_capa_error_dict_yields_nothing(self) -> None:
        assert _build(capabilities={"error": "timeout"}) == []

    def test_entropy_only_above_threshold(self) -> None:
        out = _build(entropy={".text": 6.5, ".rsrc": 7.0, ".packed": 7.91})
        assert out == [Finding(source="pefile_entropy", kind="high_entropy", value=".packed: 7.91")]

    def test_import_combo(self) -> None:
        out = _build(import_combos=["Process Injection Combo"])
        assert out == [Finding(source="import_combo", kind="behavior", value="Process Injection Combo")]

    @pytest.mark.parametrize(
        "text, kind",
        [
            ("http://evil.com/a", "url"),
            ("tcp://1.2.3.4:4444", "url"),
            ("10.0.0.1", "ip"),
            ("HKLM\\Software\\Run", "registry"),
            ("malware.exe", "file"),
        ],
    )
    def test_floss_ioc_kinds(self, text: str, kind: str) -> None:
        assert _build(ioc_strings=[text]) == [Finding(source="floss", kind=kind, value=text)]

    def test_order_is_yara_capa_combo_entropy_floss(self) -> None:
        out = _build(
            yara_results=[{"rule": "r"}],
            capabilities={"matched_rules": ["c"]},
            import_combos=["k"],
            entropy={".x": 7.5},
            ioc_strings=["1.1.1.1"],
        )
        assert [f.source for f in out] == ["yara", "capa", "import_combo", "pefile_entropy", "floss"]


class TestMergeFindings:
    def test_dedupes_and_keeps_order(self) -> None:
        a = Finding(source="yara", kind="rule", value="r")
        b = Finding(source="capa", kind="rule", value="c")
        assert merge_findings([a], [b, a]) == [a, b]

    def test_address_distinguishes(self) -> None:
        a = Finding(source="capa", kind="rule", value="c")
        b = Finding(source="capa", kind="rule", value="c", address="0x1")
        assert merge_findings([], [a, b]) == [a, b]


# --------------------------------------------------------------------------- #
# Finding modeli
# --------------------------------------------------------------------------- #
class TestFindingModel:
    def test_defaults(self) -> None:
        f = Finding(source="s", kind="k", value="v")
        assert (f.address, f.confidence) == ("", 1.0)

    def test_confidence_bounds(self) -> None:
        with pytest.raises(ValueError):
            Finding(source="s", kind="k", value="v", confidence=1.5)


# --------------------------------------------------------------------------- #
# static_feature_node
# --------------------------------------------------------------------------- #
class TestStaticFeatureNode:
    def test_collects_all_sources(self, monkeypatch) -> None:
        monkeypatch.setattr(nodes, "run_floss", lambda p: ["http://c2.example/x"])
        monkeypatch.setattr(
            nodes,
            "run_capa",
            lambda p: (
                {"matched_rules": ["create registry key"], "mitre_attack": [], "malware_behavior": []},
                [{"offset": "0x401050", "rule": "create registry key"}],
            ),
        )
        monkeypatch.setattr(nodes, "extract_imports", lambda p: ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"])
        monkeypatch.setattr(nodes, "section_entropy", lambda p: {".text": 6.0, ".upx": 7.9})

        state = AgentState(file_path="x.exe", yara_results=[{"rule": "Emotet", "tags": [], "meta": {}}])
        out = static_feature_node(state)

        got = {(f.source, f.kind, f.value, f.address) for f in out["findings"]}
        assert got == {
            ("yara", "rule", "Emotet", ""),
            ("capa", "rule", "create registry key", "0x401050"),
            ("import_combo", "behavior", "Process Injection Combo", ""),
            ("pefile_entropy", "high_entropy", ".upx: 7.90", ""),
            ("floss", "url", "http://c2.example/x", ""),
        }
        # uyumluluk alanları korunur
        assert out["ghidra_hints"] == [{"offset": "0x401050", "rule": "create registry key"}]
        assert out["capabilities"]["matched_rules"] == ["create registry key"]
        assert out["extracted_strings"] == ["http://c2.example/x"]

    def test_all_tools_failing_gives_empty_findings(self, monkeypatch) -> None:
        monkeypatch.setattr(nodes, "run_floss", lambda p: [])
        monkeypatch.setattr(nodes, "run_capa", lambda p: ({"error": "timeout"}, []))
        monkeypatch.setattr(nodes, "extract_imports", lambda p: [])
        monkeypatch.setattr(nodes, "section_entropy", lambda p: {})
        out = static_feature_node(AgentState(file_path="x"))
        assert out["findings"] == []
        assert out["ghidra_hints"] == []

    def test_does_not_duplicate_findings_from_entry_node(self, monkeypatch) -> None:
        monkeypatch.setattr(nodes, "run_floss", lambda p: [])
        monkeypatch.setattr(nodes, "run_capa", lambda p: ({}, []))
        monkeypatch.setattr(nodes, "extract_imports", lambda p: [])
        monkeypatch.setattr(nodes, "section_entropy", lambda p: {})
        yara = [{"rule": "Emotet"}]
        state = AgentState(
            file_path="x",
            yara_results=yara,
            findings=nodes.yara_findings(yara),  # entry_node zaten ekledi
        )
        assert len(static_feature_node(state)["findings"]) == 1

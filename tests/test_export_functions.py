"""export_functions.py (saf mantık), ghidra_runner.run_ghidra ve deep_inspection_node testleri."""

from __future__ import annotations

import json
import os
import subprocess

import pytest

import export_functions as ef
import ghidra_runner
import nodes
from import_combos import combo_api_map
from state import AgentState, DecompiledFunction, Finding

COMBO = {"virtualalloc", "virtualallocex", "writeprocessmemory", "createremotethread", "createremotethreadex"}


def _rec(offset, priority=0, size=100, is_library=False, callees=()):
    return {
        "offset": offset,
        "priority": priority,
        "size": size,
        "is_library": is_library,
        "callees": list(callees),
    }


# --------------------------------------------------------------------------- #
# Ghidra dışında import edilebilir mi?
# --------------------------------------------------------------------------- #
def test_module_is_importable_outside_ghidra_and_python3_clean() -> None:
    # main() çalışmamış olmalı (currentProgram yok); aksi halde import patlardı
    assert callable(ef.main)


# --------------------------------------------------------------------------- #
# compute_priority
# --------------------------------------------------------------------------- #
class TestComputePriority:
    def test_plain_function_is_zero(self) -> None:
        assert ef.compute_priority([], ["printf"], 100, False, set()) == 0

    def test_capa_hit(self) -> None:
        assert ef.compute_priority(["rule"], [], 100, False, set()) == 5

    def test_dangerous_api(self) -> None:
        assert ef.compute_priority([], ["CreateProcessW"], 100, False, set()) == 4

    def test_dangerous_api_counted_once(self) -> None:
        assert ef.compute_priority([], ["VirtualAlloc", "WinExec"], 100, False, set()) == 4

    def test_import_combo_api_adds_four(self) -> None:
        # VirtualAlloc hem tehlikeli listede hem combo'da: 4 + 4
        assert ef.compute_priority([], ["VirtualAlloc"], 100, False, COMBO) == 8

    def test_combo_ignored_when_no_active_combo(self) -> None:
        assert ef.compute_priority([], ["VirtualAlloc"], 100, False, set()) == 4

    def test_external_prefix_is_stripped(self) -> None:
        assert ef.compute_priority([], ["<EXTERNAL>::WriteProcessMemory"], 100, False, COMBO) == 8

    def test_all_bonuses_stack(self) -> None:
        assert ef.compute_priority(["r"], ["VirtualAlloc"], 100, False, COMBO) == 13

    def test_library_is_always_zero(self) -> None:
        assert ef.compute_priority(["r"], ["VirtualAlloc"], 100, True, COMBO) == 0

    def test_large_function_penalty_never_negative(self) -> None:
        assert ef.compute_priority(["r"], [], 20000, False, set()) == 3
        assert ef.compute_priority([], [], 20000, False, set()) == 0


class TestActiveComboApis:
    def test_reads_import_combo_findings(self) -> None:
        findings = [
            {"source": "capa", "value": "Process Injection Combo"},  # yanlış kaynak
            {"source": "import_combo", "value": "Process Injection Combo"},
            {"source": "import_combo", "value": "Bilinmeyen"},
            "bozuk",
        ]
        assert ef.active_combo_apis(findings, combo_api_map()) == COMBO

    def test_no_findings(self) -> None:
        assert ef.active_combo_apis([], combo_api_map()) == set()


# --------------------------------------------------------------------------- #
# plan_export (Top-N, fallback, stub'lar)
# --------------------------------------------------------------------------- #
class TestPlanExport:
    def test_only_positive_priority_sorted_and_capped(self) -> None:
        records = [_rec(f"0x{i}", priority=1 + (i % 7)) for i in range(300)]
        records += [_rec("0xzero", priority=0)]
        chosen, _ = ef.plan_export(records)
        assert len(chosen) == ef.MAX_DECOMPILE == 100
        assert all(r["priority"] > 0 for r in chosen)
        prios = [r["priority"] for r in chosen]
        assert prios == sorted(prios, reverse=True)
        assert prios[0] == 7

    def test_tie_prefers_smaller_function(self) -> None:
        chosen, _ = ef.plan_export([_rec("0xa", 5, size=500), _rec("0xb", 5, size=50)])
        assert [r["offset"] for r in chosen] == ["0xb", "0xa"]

    def test_fallback_when_nothing_scored(self) -> None:
        records = [_rec(f"0x{i}", 0, size=10 + i) for i in range(50)]
        records.append(_rec("0xlib", 0, size=999, is_library=True))
        records.append(_rec("0xhuge", 0, size=50000))
        chosen, _ = ef.plan_export(records)
        assert len(chosen) == ef.FALLBACK_DECOMPILE
        offsets = {r["offset"] for r in chosen}
        assert "0xlib" not in offsets and "0xhuge" not in offsets
        assert chosen[0]["size"] == 59  # en büyük uygun fonksiyon önce

    def test_empty_program(self) -> None:
        assert ef.plan_export([]) == ([], [])

    def test_stubs_are_direct_internal_callees_only(self) -> None:
        records = [
            _rec("0x1", 5, callees=["0x2", "0xext", "0x1"]),
            _rec("0x2", 0, callees=["0x3"]),  # 2. seviye: eklenmez
            _rec("0x3", 0),
            _rec("0x4", 0),  # alakasız
        ]
        chosen, stubs = ef.plan_export(records)
        assert [r["offset"] for r in chosen] == ["0x1"]
        assert [r["offset"] for r in stubs] == ["0x2"]

    def test_stub_not_duplicated_when_already_chosen(self) -> None:
        records = [_rec("0x1", 5, callees=["0x2"]), _rec("0x2", 4)]
        chosen, stubs = ef.plan_export(records)
        assert len(chosen) == 2 and stubs == []

    def test_stub_cap(self) -> None:
        callees = [f"0xc{i}" for i in range(ef.MAX_STUBS + 50)]
        records = [_rec("0x1", 5, callees=callees)] + [_rec(c, 0) for c in callees]
        _, stubs = ef.plan_export(records)
        assert len(stubs) == ef.MAX_STUBS


class TestReadInput:
    def test_valid(self, tmp_path) -> None:
        path = tmp_path / "in.json"
        path.write_text(json.dumps({"hints": [{"offset": "0x1"}], "findings": [{"a": 1}], "combo_apis": {"x": ["y"]}}))
        assert ef.read_input(str(path)) == ([{"offset": "0x1"}], [{"a": 1}], {"x": ["y"]})

    def test_wrong_types_fall_back(self, tmp_path) -> None:
        path = tmp_path / "in.json"
        path.write_text(json.dumps({"hints": "x", "findings": None, "combo_apis": []}))
        assert ef.read_input(str(path)) == ([], [], {})

    def test_write_results_roundtrip(self, tmp_path) -> None:
        path = tmp_path / "out.json"
        ef.write_results(str(path), [{"c_code": "int ü(){}"}])
        assert json.loads(path.read_text(encoding="utf-8")) == [{"c_code": "int ü(){}"}]


# --------------------------------------------------------------------------- #
# ghidra_runner.run_ghidra
# --------------------------------------------------------------------------- #
class TestRunGhidra:
    def _patch(self, monkeypatch, fake_run):
        monkeypatch.setattr(ghidra_runner, "_find_analyze_headless", lambda: "analyzeHeadless")
        monkeypatch.setattr(ghidra_runner.subprocess, "run", fake_run)

    def test_writes_combined_input_and_parses_output(self, monkeypatch) -> None:
        seen = {}

        def fake_run(cmd, **kwargs):
            i = cmd.index("-postScript")
            assert cmd[i + 1] == "export_functions.py"
            input_path, out_path = cmd[i + 2], cmd[i + 3]
            assert os.path.basename(input_path) == "ghidra_input.json"
            seen["dir"] = os.path.dirname(input_path)
            seen["input"] = json.load(open(input_path, encoding="utf-8"))
            seen["timeout"] = kwargs["timeout"]
            seen["cmd"] = cmd
            with open(out_path, "w", encoding="utf-8") as fh:
                json.dump(
                    [
                        {"offset": "0x1", "name": "f", "priority": 9, "c_code": "int f(){}", "xrefs": ["0x5"],
                         "decompile_warnings": ["w"], "callees": ["0x2"], "size": 10, "is_library": False},
                        {"bozuk": True},  # offset yok -> atlanır
                    ],
                    fh,
                )
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self._patch(monkeypatch, fake_run)
        hints = [{"offset": "0x401000", "rule": "r"}]
        findings = [Finding(source="import_combo", kind="behavior", value="Process Injection Combo")]

        out = ghidra_runner.run_ghidra("sample.exe", hints, findings)

        assert [f.offset for f in out] == ["0x1"]
        assert out[0].xrefs == ["0x5"] and out[0].decompile_warnings == ["w"]
        assert seen["timeout"] == 600
        assert seen["input"]["hints"] == hints
        assert seen["input"]["findings"][0]["source"] == "import_combo"
        assert "process injection combo" in {k.lower() for k in seen["input"]["combo_apis"]}
        assert seen["cmd"][seen["cmd"].index("-import") + 1] == "sample.exe"
        assert "-deleteProject" in seen["cmd"]
        assert not os.path.exists(seen["dir"])  # temp klasör temizlendi

    def test_runs_even_with_empty_hints_and_findings(self, monkeypatch) -> None:
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="x")

        self._patch(monkeypatch, fake_run)
        assert ghidra_runner.run_ghidra("s.exe", []) == []
        assert len(calls) == 1  # Ghidra yine de çağrıldı

    def test_accepts_dict_findings(self, monkeypatch) -> None:
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["input"] = json.load(open(cmd[cmd.index("-postScript") + 2], encoding="utf-8"))
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")

        self._patch(monkeypatch, fake_run)
        ghidra_runner.run_ghidra("s", [], [{"source": "x", "value": "y"}])
        assert captured["input"]["findings"] == [{"source": "x", "value": "y"}]

    @pytest.mark.parametrize("exc", [subprocess.TimeoutExpired("a", 600), FileNotFoundError("x"), RuntimeError("y")])
    def test_errors_return_empty_and_clean_up(self, monkeypatch, exc: Exception) -> None:
        def fake_run(cmd, **kwargs):
            raise exc

        self._patch(monkeypatch, fake_run)
        assert ghidra_runner.run_ghidra("s", []) == []

    def test_tool_missing(self, monkeypatch) -> None:
        monkeypatch.setattr(ghidra_runner, "_find_analyze_headless", lambda: None)
        assert ghidra_runner.run_ghidra("s", []) == []


class TestDeepInspectionNode:
    def test_passes_hints_and_findings(self, monkeypatch) -> None:
        captured = {}

        def fake_run_ghidra(path, hints, findings=None):
            captured.update(path=path, hints=hints, findings=findings)
            return [DecompiledFunction(offset="0x1", c_code="x")]

        monkeypatch.setattr(nodes, "run_ghidra", fake_run_ghidra)
        finding = Finding(source="import_combo", kind="behavior", value="Process Injection Combo")
        state = AgentState(
            file_path="a.exe", route_flag="native", ghidra_hints=[{"offset": "0x1", "rule": "r"}], findings=[finding]
        )

        out = nodes.deep_inspection_node(state)

        assert captured == {"path": "a.exe", "hints": state.ghidra_hints, "findings": [finding]}
        assert [f.offset for f in out["source_code"]] == ["0x1"]

    def test_empty_result_is_passed_through(self, monkeypatch) -> None:
        monkeypatch.setattr(nodes, "run_ghidra", lambda *a, **k: [])
        assert nodes.deep_inspection_node(AgentState(file_path="x", route_flag="native")) == {"source_code": []}


class TestDeepInspectionGuard:
    @staticmethod
    def _boom(monkeypatch):
        def boom(*a, **k):
            raise AssertionError("Ghidra çalıştırılmamalı")

        monkeypatch.setattr(nodes, "run_ghidra", boom)

    def test_skips_when_source_code_present(self, monkeypatch) -> None:
        self._boom(monkeypatch)
        state = AgentState(
            file_path="x", route_flag="native", source_code=[DecompiledFunction(offset="", c_code="print(1)")]
        )
        assert nodes.deep_inspection_node(state) == {}

    @pytest.mark.parametrize("route", ["python", "dotnet", "fast_track", None])
    def test_skips_when_route_not_native(self, monkeypatch, route) -> None:
        self._boom(monkeypatch)
        assert nodes.deep_inspection_node(AgentState(file_path="x", route_flag=route)) == {}


def test_linux_dangerous_apis_raise_priority():
    for api in ("socket", "connect", "send", "execve", "system", "dlsym", "ptrace", "mprotect"):
        assert ef.compute_priority([], [api], 100, False, set()) == 4


def test_propagate_priority_raises_direct_callee():
    records = [
        {"offset": "0x1", "priority": 5, "callees": ["0x2"], "is_library": False},
        {"offset": "0x2", "priority": 0, "callees": [], "is_library": False},
        {"offset": "0x3", "priority": 0, "callees": [], "is_library": True},
    ]
    ef.propagate_priority(records)
    assert records[1]["priority"] == 4
    assert records[2]["priority"] == 0


# --------------------------------------------------------------------------- #
# Adım 5: adressiz IoC string'i -> fonksiyon eşleme
# --------------------------------------------------------------------------- #
class TestCollectTargetIocs:
    def test_only_ioc_kinds_are_collected(self) -> None:
        findings = [
            {"source": "floss", "kind": "ip", "value": "10.0.0.1"},
            {"source": "floss", "kind": "url", "value": "http://evil.example/gate.php"},
            {"source": "x", "kind": "domain", "value": "evil.example"},
            {"source": "floss", "kind": "registry", "value": "HKLM\\Software\\Run"},
            {"source": "floss", "kind": "file", "value": "dropper.exe"},
            {"source": "x", "kind": "email", "value": "bad@evil.example"},
            {"source": "capa", "kind": "rule", "value": "encrypt data using AES"},  # IoC türü değil
            {"source": "import_combo", "kind": "behavior", "value": "Process Injection Combo"},
        ]
        assert ef.collect_target_iocs(findings) == {
            "10.0.0.1", "http://evil.example/gate.php", "evil.example",
            "HKLM\\Software\\Run", "dropper.exe", "bad@evil.example",
        }

    def test_ignores_garbage_short_and_non_dict(self) -> None:
        findings = ["x", None, {"kind": "ip"}, {"kind": "ip", "value": 5}, {"kind": "file", "value": "a.b"},
                    {"kind": "ip", "value": "  1.2.3.4  "}]
        assert ef.collect_target_iocs(findings) == {"1.2.3.4"}

    def test_cap(self, monkeypatch) -> None:
        monkeypatch.setattr(ef, "MAX_TARGET_IOCS", 3)
        findings = [{"kind": "file", "value": f"file{i}.exe"} for i in range(10)]
        assert len(ef.collect_target_iocs(findings)) == 3


class TestMatchIocs:
    INDEX = ef.build_ioc_index({"10.0.0.1", "http://Evil.example/gate.php", "evil.example"})

    def test_equal_and_contains(self) -> None:
        assert ef.match_iocs("10.0.0.1", self.INDEX) == ["10.0.0.1"]
        text = "GET http://evil.example/gate.php HTTP/1.1"
        assert sorted(ef.match_iocs(text, self.INDEX)) == ["evil.example", "http://Evil.example/gate.php"]

    def test_case_insensitive_returns_original_spelling(self) -> None:
        # eşleşme büyük/küçük harf duyarsız; dönen değer findings'teki orijinal yazım
        assert sorted(ef.match_iocs("HTTP://EVIL.EXAMPLE/GATE.PHP", self.INDEX)) == [
            "evil.example", "http://Evil.example/gate.php",
        ]

    def test_no_match_and_short_strings(self) -> None:
        assert ef.match_iocs("hello world", self.INDEX) == []
        assert ef.match_iocs("", self.INDEX) == []
        assert ef.match_iocs("a", self.INDEX) == []

    def test_reverse_containment_is_not_matched(self) -> None:
        # bellekteki kısa string IoC'nin parçası olsa bile eşleşmemeli
        assert ef.match_iocs("evil", self.INDEX) == []


class TestIocScoring:
    def test_ioc_bonus_is_three_and_applied_once(self) -> None:
        assert ef.compute_priority([], [], 100, False, set(), ["a", "b", "c"]) == 3
        assert ef.compute_priority([], [], 100, False, set(), []) == 0
        assert ef.compute_priority([], [], 100, False, set(), None) == 0

    def test_stacks_with_other_bonuses(self) -> None:
        assert ef.compute_priority(["r"], ["VirtualAlloc"], 100, False, COMBO, ["x"]) == 5 + 4 + 4 + 3

    def test_library_stays_zero(self) -> None:
        assert ef.compute_priority([], [], 100, True, set(), ["x"]) == 0

    def test_large_penalty_still_applies(self) -> None:
        assert ef.compute_priority([], [], 20000, False, set(), ["x"]) == 1

    def test_add_ioc_hits_dedupes_and_caps(self, monkeypatch) -> None:
        hits: dict = {}
        ef.add_ioc_hits(hits, "0x1", ["a", "b", "a"])
        ef.add_ioc_hits(hits, "0x1", ["b", "c"])
        assert hits == {"0x1": ["a", "b", "c"]}
        monkeypatch.setattr(ef, "MAX_IOCS_PER_FUNCTION", 2)
        ef.add_ioc_hits(hits, "0x2", ["a", "b", "c"])
        assert hits["0x2"] == ["a", "b"]


# --- Ghidra API'sini taklit eden küçük sahte nesneler -------------------------------------------
class _Addr:
    def __init__(self, offset, memory=True):
        self.offset, self.memory = offset, memory

    def getOffset(self):
        return self.offset

    def isMemoryAddress(self):
        return self.memory

    def add(self, delta):
        return _Addr(self.offset + delta, self.memory)


class _Data:
    def __init__(self, offset, value):
        self.addr, self.value = _Addr(offset), value

    def getValue(self):
        return self.value

    def getDefaultValueRepresentation(self):
        return f'"{self.value}"'

    def getAddress(self):
        return self.addr


class _Ref:
    def __init__(self, source):
        self.source = source

    def getFromAddress(self):
        return self.source


class _Func:
    def __init__(self, entry, size=0x40, name=None, thunk=False, callees=()):
        self.entry, self.size, self.name, self.thunk, self.callees = entry, size, name or f"FUN_{entry:x}", thunk, callees

    def getEntryPoint(self):
        return _Addr(self.entry)

    def contains(self, offset):
        return self.entry <= offset < self.entry + self.size

    def isExternal(self):
        return False

    def isThunk(self):
        return self.thunk

    def getName(self):
        return self.name

    def getBody(self):
        size = self.size
        return type("B", (), {"getNumAddresses": lambda s: size})()

    def getCalledFunctions(self, monitor):
        return list(self.callees)


class _Program:
    def __init__(self, strings, refs, functions):
        self.strings, self.refs, self.functions = strings, refs, functions

    def getReferenceManager(self):
        prog = self
        return type("RM", (), {"getReferencesTo": lambda s, addr: prog.refs.get(addr.getOffset(), [])})()

    def getFunctionManager(self):
        prog = self

        def containing(s, addr):
            return next((f for f in prog.functions if f.contains(addr.getOffset())), None)

        return type("FM", (), {
            "getFunctionContaining": containing,
            "getFunctions": lambda s, forward: list(prog.functions),
        })()


@pytest.fixture
def fake_ghidra(monkeypatch):
    import sys
    import types

    def install(program):
        monkeypatch.setattr(ef, "currentProgram", program, raising=False)
        errors: list[str] = []
        monkeypatch.setattr(ef, "printerr", errors.append, raising=False)

        iterator = type("DefinedDataIterator", (), {"definedStrings": staticmethod(lambda prog: list(prog.strings))})
        util = types.ModuleType("ghidra.program.util")
        util.DefinedDataIterator = iterator
        task = types.ModuleType("ghidra.util.task")
        task.TaskMonitor = type("TaskMonitor", (), {"DUMMY": object()})
        for name, mod in {
            "ghidra": types.ModuleType("ghidra"), "ghidra.program": types.ModuleType("ghidra.program"),
            "ghidra.program.util": util, "ghidra.util": types.ModuleType("ghidra.util"), "ghidra.util.task": task,
        }.items():
            monkeypatch.setitem(sys.modules, name, mod)
        return errors

    return install


class TestMapIocsToFunctions:
    def _program(self):
        f1, f2, f3 = _Func(0x401000), _Func(0x401100), _Func(0x401200)
        strings = [
            _Data(0x500000, "http://evil.example/gate.php"),
            _Data(0x500100, "10.0.0.1"),
            _Data(0x500200, "Hello, world"),               # IoC değil
            _Data(0x500300, "GET /a HTTP/1.1 Host: EVIL.EXAMPLE"),  # IoC'yi içerir
        ]
        refs = {
            0x500000: [_Ref(_Addr(0x401010)), _Ref(_Addr(0x401110))],  # f1 ve f2
            0x500100: [_Ref(_Addr(0x401120)), _Ref(_Addr(0x600000, memory=False))],  # f2 + bellek dışı
            0x500200: [_Ref(_Addr(0x401210))],                         # f3 ama eşleşmeyen string
            0x500300: [_Ref(_Addr(0x700000))],                         # hiçbir fonksiyonda değil
        }
        return _Program(strings, refs, [f1, f2, f3])

    def test_maps_string_references_to_containing_functions(self, fake_ghidra) -> None:
        errors = fake_ghidra(self._program())
        hits = ef.map_iocs_to_functions({"http://evil.example/gate.php", "10.0.0.1"})
        assert hits == {
            "0x401000": ["http://evil.example/gate.php"],
            "0x401100": ["http://evil.example/gate.php", "10.0.0.1"],
        }
        assert errors == []

    def test_containing_string_matches_and_non_function_reference_is_dropped(self, fake_ghidra) -> None:
        # "evil.example" hem URL string'inin içinde (f1, f2 referans verir) hem de "...Host: EVIL.EXAMPLE"
        # string'inde geçer; ikincisine yalnızca fonksiyon dışından (0x700000) referans var -> yok sayılır.
        fake_ghidra(self._program())
        assert ef.map_iocs_to_functions({"evil.example"}) == {
            "0x401000": ["evil.example"],
            "0x401100": ["evil.example"],
        }

    def test_no_targets_returns_empty_without_scanning(self, fake_ghidra) -> None:
        fake_ghidra(None)  # currentProgram'a dokunulursa AttributeError olurdu
        assert ef.map_iocs_to_functions(set()) == {}

    def test_string_error_is_skipped_not_fatal(self, fake_ghidra) -> None:
        prog = self._program()

        class Broken(_Data):
            def getValue(self):
                raise RuntimeError("bozuk string")

        prog.strings.insert(0, Broken(0x500400, "x"))
        errors = fake_ghidra(prog)
        hits = ef.map_iocs_to_functions({"10.0.0.1"})
        assert hits == {"0x401100": ["10.0.0.1"]}
        assert any("string islenemedi" in e for e in errors)

    def test_total_failure_returns_partial_empty(self, fake_ghidra) -> None:
        errors = fake_ghidra(None)  # getReferenceManager çağrısı patlar
        assert ef.map_iocs_to_functions({"10.0.0.1"}) == {}
        assert any("IoC eslemesi basarisiz" in e for e in errors)


class TestCollectRecordsWithIocs:
    def test_records_get_iocs_and_bonus(self, fake_ghidra) -> None:
        f1, f2 = _Func(0x401000), _Func(0x401100)
        fake_ghidra(_Program([], {}, [f1, f2]))
        records = ef.collect_records({}, set(), {"0x401100": ["10.0.0.1"]})
        by_offset = {r["offset"]: r for r in records}
        assert by_offset["0x401000"]["iocs"] == [] and by_offset["0x401000"]["priority"] == 0
        assert by_offset["0x401100"]["iocs"] == ["10.0.0.1"] and by_offset["0x401100"]["priority"] == 3

    def test_ioc_function_becomes_a_decompile_candidate(self, fake_ghidra) -> None:
        f1, f2 = _Func(0x401000), _Func(0x401100)
        fake_ghidra(_Program([], {}, [f1, f2]))
        records = ef.collect_records({}, set(), {"0x401100": ["10.0.0.1"]})
        chosen, _ = ef.plan_export(records)
        assert [r["offset"] for r in chosen] == ["0x401100"]

    def test_thunk_with_ioc_keeps_zero_priority(self, fake_ghidra) -> None:
        fake_ghidra(_Program([], {}, [_Func(0x401000, thunk=True)]))
        (record,) = ef.collect_records({}, set(), {"0x401000": ["10.0.0.1"]})
        assert record["priority"] == 0

    def test_without_ioc_hits_behaves_as_before(self, fake_ghidra) -> None:
        fake_ghidra(_Program([], {}, [_Func(0x401000)]))
        (record,) = ef.collect_records({}, set())
        assert record["iocs"] == [] and record["priority"] == 0


class TestIocsContract:
    def test_decompiled_function_accepts_iocs_from_script_output(self) -> None:
        fn = DecompiledFunction(**{"offset": "0x1", "iocs": ["10.0.0.1"], "c_code": "x"})
        assert fn.iocs == ["10.0.0.1"]
        assert DecompiledFunction(offset="0x1").iocs == []

    def test_run_ghidra_passes_ioc_findings_in_and_parses_iocs_out(self, monkeypatch) -> None:
        seen = {}

        def fake_run(cmd, **kwargs):
            i = cmd.index("-postScript")
            seen["input"] = json.load(open(cmd[i + 2], encoding="utf-8"))
            with open(cmd[i + 3], "w", encoding="utf-8") as fh:
                json.dump([{"offset": "0x1", "name": "f", "priority": 3, "c_code": "", "iocs": ["10.0.0.1"]}], fh)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        monkeypatch.setattr(ghidra_runner, "_find_analyze_headless", lambda: "analyzeHeadless")
        monkeypatch.setattr(ghidra_runner.subprocess, "run", fake_run)
        findings = [Finding(source="floss", kind="ip", value="10.0.0.1")]

        result = ghidra_runner.run_ghidra("sample.exe", [], findings)

        # betiğin IoC'leri toplayabilmesi için kind/value girdi JSON'una ulaşmalı
        assert {(f["kind"], f["value"]) for f in seen["input"]["findings"]} == {("ip", "10.0.0.1")}
        assert ef.collect_target_iocs(seen["input"]["findings"]) == {"10.0.0.1"}
        assert [f.iocs for f in result] == [["10.0.0.1"]]


def test_compiler_stub_clone_is_not_dangerous():
    assert ef.compute_priority([], ["deregister_tm_clones"], 100, False, set()) == 0
    assert ef.compute_priority([], ["register_tm_clones"], 100, False, set()) == 0


def test_linux_exact_match_does_not_hit_substrings():
    assert ef.compute_priority([], ["clone"], 100, False, set()) == 4
    assert ef.compute_priority([], ["system"], 100, False, set()) == 4
    assert ef.compute_priority([], ["filesystem"], 100, False, set()) == 0


def test_main_is_always_chosen_even_with_scored_stubs():
    records = [_rec("0x1", 4), _rec("0x2", 4), _rec("0xm", 0)]
    records[2]["name"] = "main"
    chosen, _ = ef.plan_export(records)
    offsets = [r["offset"] for r in chosen]
    assert "0xm" in offsets
    assert offsets[0] == "0xm"


def test_entry_flag_is_chosen():
    records = [_rec("0x1", 4), _rec("0xe", 0)]
    records[1]["is_entry"] = True
    chosen, _ = ef.plan_export(records)
    assert "0xe" in [r["offset"] for r in chosen]


def test_ioc_offset_inside_defined_string(fake_ghidra):
    # Ghidra may keep a leading byte (e.g. "?http://..."); the code reference can
    # point at the URL start, one byte into the defined data.
    prog = _Program(
        [_Data(0x500000, "?http://evil.example/gate.php")],
        {0x500001: [_Ref(_Addr(0x401010))]},
        [_Func(0x401000)],
    )
    fake_ghidra(prog)
    assert ef.map_iocs_to_functions({"http://evil.example/gate.php"}) == {
        "0x401000": ["http://evil.example/gate.php"]
    }

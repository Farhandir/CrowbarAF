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

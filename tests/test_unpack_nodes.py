"""Unit tests for unpack_python_node and unpack_dotnet_node (tools are fake)."""

from __future__ import annotations

import os
import subprocess

import pytest

import nodes
from nodes import _find_main_pyc, unpack_dotnet_node, unpack_python_node
from state import AgentState, SampleInfo


def _state(path, route: str) -> AgentState:
    return AgentState(file_path=str(path), sample=SampleInfo(route=route))


def _ok(cmd, stdout="", code=0, stderr=""):
    return subprocess.CompletedProcess(cmd, code, stdout=stdout, stderr=stderr)


def _no_tools(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("tool must not be called")

    monkeypatch.setattr(nodes.subprocess, "run", boom)


# --------------------------------------------------------------------------- #
# _find_main_pyc
# --------------------------------------------------------------------------- #
class TestFindMainPyc:
    @staticmethod
    def _make(tmp_path, files: dict[str, int]):
        for name, size in files.items():
            (tmp_path / name).write_bytes(b"x" * size)
        return str(tmp_path)

    def test_prefers_name_matching_exe(self, tmp_path) -> None:
        d = self._make(tmp_path, {"pyiboot01_bootstrap.pyc": 9999, "helper.pyc": 5000, "app.pyc": 10})
        assert os.path.basename(_find_main_pyc(d, "app", "")) == "app.pyc"

    def test_name_match_is_case_insensitive(self, tmp_path) -> None:
        d = self._make(tmp_path, {"App.pyc": 10, "other.pyc": 99})
        assert os.path.basename(_find_main_pyc(d, "app", "")) == "App.pyc"

    def test_uses_extractor_entry_point_and_skips_pyi(self, tmp_path) -> None:
        d = self._make(tmp_path, {"pyiboot01_bootstrap.pyc": 1, "pyi_rth_x.pyc": 1, "real.pyc": 5, "big.pyc": 500})
        out = (
            "[+] Possible entry point: pyiboot01_bootstrap.pyc\n"
            "[+] Possible entry point: pyi_rth_x.pyc\n"
            "[+] Possible entry point: real.pyc\n"
        )
        assert os.path.basename(_find_main_pyc(d, "unrelated", out)) == "real.pyc"

    def test_falls_back_to_largest_app_pyc(self, tmp_path) -> None:
        d = self._make(tmp_path, {"pyiboot01.pyc": 9999, "a.pyc": 5, "b.pyc": 50})
        assert os.path.basename(_find_main_pyc(d, "x", "")) == "b.pyc"

    def test_none_when_only_pyi_or_empty(self, tmp_path) -> None:
        d = self._make(tmp_path, {"pyiboot01.pyc": 1, "notes.txt": 1})
        assert _find_main_pyc(d, "x", "") is None

    def test_missing_dir(self, tmp_path) -> None:
        assert _find_main_pyc(str(tmp_path / "missing"), "x", "") is None


# --------------------------------------------------------------------------- #
# unpack_python_node
# --------------------------------------------------------------------------- #
class TestUnpackPython:
    @pytest.mark.parametrize("route", ["native", "dotnet", "fast_track"])
    def test_wrong_route_does_nothing(self, tmp_path, monkeypatch, route: str) -> None:
        _no_tools(monkeypatch)
        assert unpack_python_node(_state(tmp_path / "a.exe", route)) == {}

    def _fake(self, cdc_ok=True, decompyle_ok=False, calls=None):
        def fake_run(cmd, **kwargs):
            if calls is not None:
                calls.append((cmd, kwargs))
            tool = cmd[0]
            if tool == "pyinstxtractor":
                out = os.path.join(kwargs["cwd"], os.path.basename(cmd[1]) + "_extracted")
                os.makedirs(out)
                open(os.path.join(out, "app.pyc"), "wb").write(b"pyc")
                open(os.path.join(out, "pyiboot01_bootstrap.pyc"), "wb").write(b"pyc")
                return _ok(cmd, stdout="[+] Possible entry point: app.pyc")
            if tool == "pycdc":
                return _ok(cmd, stdout="print('hi')\n") if cdc_ok else _ok(cmd, code=1, stderr="fail")
            if tool == "decompyle3":
                return _ok(cmd, stdout="print('from decompyle3')\n") if decompyle_ok else _ok(cmd, code=1)
            raise AssertionError(tool)

        return fake_run

    def test_success(self, tmp_path, monkeypatch) -> None:
        calls = []
        monkeypatch.setattr(nodes.subprocess, "run", self._fake(calls=calls))
        src = tmp_path / "app.exe"
        src.write_bytes(b"MZ")

        out = unpack_python_node(_state(src, "python"))

        [func] = out["source_code"]
        assert (func.name, func.priority, func.c_code) == ("main_script", 10, "print('hi')\n")
        assert (func.callees, func.capa_hits, func.llm_summary, func.size) == ([], [], "", 0)
        extractor_cmd, extractor_kwargs = calls[0]
        assert extractor_cmd == ["pyinstxtractor", os.path.abspath(src)]
        assert extractor_kwargs["timeout"] == 60
        assert extractor_kwargs["cwd"] != str(tmp_path)  # the directory next to the sample is not polluted
        assert calls[1][0][0] == "pycdc" and calls[1][1]["timeout"] == 60
        assert not os.path.exists(extractor_kwargs["cwd"])  # temp directory cleaned up
        assert list(tmp_path.iterdir()) == [src]

    def test_falls_back_to_decompyle3(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setattr(nodes.subprocess, "run", self._fake(cdc_ok=False, decompyle_ok=True))
        out = unpack_python_node(_state(tmp_path / "app.exe", "python"))
        assert out["source_code"][0].c_code == "print('from decompyle3')\n"

    def test_both_decompilers_fail(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setattr(nodes.subprocess, "run", self._fake(cdc_ok=False, decompyle_ok=False))
        assert unpack_python_node(_state(tmp_path / "app.exe", "python")) == {"route_flag": "native"}

    def test_empty_decompiler_output_is_failure(self, tmp_path, monkeypatch) -> None:
        def fake_run(cmd, **kwargs):
            if cmd[0] == "pyinstxtractor":
                out = os.path.join(kwargs["cwd"], "app.exe_extracted")
                os.makedirs(out)
                open(os.path.join(out, "app.pyc"), "wb").write(b"x")
                return _ok(cmd)
            return _ok(cmd, stdout="   \n")

        monkeypatch.setattr(nodes.subprocess, "run", fake_run)
        assert unpack_python_node(_state(tmp_path / "app.exe", "python")) == {"route_flag": "native"}

    def test_extractor_makes_no_output_dir(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setattr(nodes.subprocess, "run", lambda cmd, **k: _ok(cmd))
        assert unpack_python_node(_state(tmp_path / "app.exe", "python")) == {"route_flag": "native"}

    @pytest.mark.parametrize("exc", [FileNotFoundError("x"), subprocess.TimeoutExpired("x", 60), OSError("y")])
    def test_tool_errors_return_empty(self, tmp_path, monkeypatch, exc: Exception) -> None:
        def boom(*a, **k):
            raise exc

        monkeypatch.setattr(nodes.subprocess, "run", boom)
        assert unpack_python_node(_state(tmp_path / "app.exe", "python")) == {"route_flag": "native"}


# --------------------------------------------------------------------------- #
# unpack_dotnet_node
# --------------------------------------------------------------------------- #
class TestUnpackDotnet:
    @pytest.mark.parametrize("route", ["native", "python", "fast_track"])
    def test_wrong_route_does_nothing(self, tmp_path, monkeypatch, route: str) -> None:
        _no_tools(monkeypatch)
        assert unpack_dotnet_node(_state(tmp_path / "a.exe", route)) == {}

    def test_success_and_cleanup(self, tmp_path, monkeypatch) -> None:
        calls = []
        src = tmp_path / "app.exe"
        src.write_bytes(b"MZ")
        clean = str(src) + ".clean"

        def fake_run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            if cmd[0] == "de4dot":
                open(cmd[3], "wb").write(b"clean")
                return _ok(cmd)
            if cmd[0] == "ilspycmd":
                assert os.path.exists(cmd[1])  # cleaned file exists when passed to ilspycmd
                return _ok(cmd, stdout="class Program { }\n")
            raise AssertionError(cmd)

        monkeypatch.setattr(nodes.subprocess, "run", fake_run)
        out = unpack_dotnet_node(_state(src, "dotnet"))

        [func] = out["source_code"]
        assert (func.name, func.priority, func.c_code) == ("dotnet_source", 10, "class Program { }\n")
        assert calls[0][0] == ["de4dot", str(src), "-o", clean]
        assert calls[0][1]["timeout"] == 60
        assert calls[1][0] == ["ilspycmd", clean]
        assert not os.path.exists(clean)  # no artifact is left behind
        assert list(tmp_path.iterdir()) == [src]

    def test_stale_clean_file_removed_before_run(self, tmp_path, monkeypatch) -> None:
        src = tmp_path / "app.exe"
        stale = tmp_path / "app.exe.clean"
        stale.write_bytes(b"old")
        seen = {}

        def fake_run(cmd, **kwargs):
            if cmd[0] == "de4dot":
                seen["existed"] = stale.exists()
                return _ok(cmd, code=1)
            raise AssertionError(cmd)

        monkeypatch.setattr(nodes.subprocess, "run", fake_run)
        assert unpack_dotnet_node(_state(src, "dotnet")) == {"route_flag": "native"}
        assert seen["existed"] is False

    def test_de4dot_failure_skips_ilspy(self, tmp_path, monkeypatch) -> None:
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd[0])
            return _ok(cmd, code=1, stderr="bad")

        monkeypatch.setattr(nodes.subprocess, "run", fake_run)
        assert unpack_dotnet_node(_state(tmp_path / "a.exe", "dotnet")) == {"route_flag": "native"}
        assert calls == ["de4dot"]

    def test_de4dot_without_output_file(self, tmp_path, monkeypatch) -> None:
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd[0])
            return _ok(cmd)  # looks successful but no file exists

        monkeypatch.setattr(nodes.subprocess, "run", fake_run)
        assert unpack_dotnet_node(_state(tmp_path / "a.exe", "dotnet")) == {"route_flag": "native"}
        assert calls == ["de4dot"]

    def test_ilspy_failure_cleans_up(self, tmp_path, monkeypatch) -> None:
        src = tmp_path / "a.exe"

        def fake_run(cmd, **kwargs):
            if cmd[0] == "de4dot":
                open(cmd[3], "wb").write(b"c")
                return _ok(cmd)
            return _ok(cmd, code=1, stderr="boom")

        monkeypatch.setattr(nodes.subprocess, "run", fake_run)
        assert unpack_dotnet_node(_state(src, "dotnet")) == {"route_flag": "native"}
        assert not os.path.exists(str(src) + ".clean")

    @pytest.mark.parametrize("exc", [FileNotFoundError("de4dot"), subprocess.TimeoutExpired("de4dot", 60), OSError("y")])
    def test_tool_errors_return_empty(self, tmp_path, monkeypatch, exc: Exception) -> None:
        def boom(*a, **k):
            raise exc

        monkeypatch.setattr(nodes.subprocess, "run", boom)
        assert unpack_dotnet_node(_state(tmp_path / "a.exe", "dotnet")) == {"route_flag": "native"}


class TestNativeFallbackReachesGhidra:
    @pytest.mark.parametrize("route, node", [("python", unpack_python_node), ("dotnet", unpack_dotnet_node)])
    def test_failed_unpack_lets_ghidra_run(self, tmp_path, monkeypatch, route, node) -> None:
        monkeypatch.setattr(nodes.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError("x")))
        state = _state(tmp_path / "a.exe", route)
        state = state.model_copy(update={"route_flag": route, **node(state)})
        assert state.route_flag == "native"

        called = []
        monkeypatch.setattr(nodes, "run_ghidra", lambda *a, **k: called.append(1) or [])
        nodes.deep_inspection_node(state)
        assert called == [1]

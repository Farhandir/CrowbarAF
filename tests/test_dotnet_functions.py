"""Tests for analyzers.dotnet_functions with synthetic metadata and C# only."""

from __future__ import annotations

import pytest

from analyzers import dotnet_functions as df
from analyzers.dotnet_functions import DOTNET_DANGEROUS_APIS, build_dotnet_functions
from analyzers.dotnet_methods import DotnetMethod
from analyzers.dotnet_source import CSharpMember
from state import Finding

T1 = 0x06000001
T2 = 0x06000002
T3 = 0x06000003
T4 = 0x06000004
T5 = 0x06000005


@pytest.fixture(autouse=True)
def _clean_selection_env(monkeypatch):
    for name in (
        "CROWBAR_DECOMPILE_MODE",
        "CROWBAR_AUTO_ALL_CAP",
        "CROWBAR_AUTO_TOP_N",
        "CROWBAR_MAX_DECOMPILE",
    ):
        monkeypatch.delenv(name, raising=False)


def _method(
    token: int,
    type_name: str,
    name: str,
    *,
    params: int = 0,
    il_size: int = 20,
    callees: list[int] | None = None,
    api_refs: list[str] | None = None,
    strings: list[str] | None = None,
    generated: bool = False,
    has_body: bool = True,
) -> DotnetMethod:
    return DotnetMethod(
        token=token,
        type_name=type_name,
        name=name,
        param_count=params,
        il_size=il_size,
        callees=list(callees or []),
        api_refs=list(api_refs or []),
        strings=list(strings or []),
        is_generated=generated,
        has_body=has_body,
    )


def _member(type_name: str, name: str, code: str, *, params: int = 0) -> CSharpMember:
    return CSharpMember(type_name, name, params, code, "Sample.cs", 1)


def _install(monkeypatch, methods, members, files=None):
    monkeypatch.setattr(df, "extract_dotnet_methods", lambda path, *a, **k: methods)
    monkeypatch.setattr(
        df,
        "run_ilspy_project",
        lambda target, timeout: {"Sample.cs": "source"} if files is None else files,
    )
    monkeypatch.setattr(df, "split_csharp_members", lambda cs_files: members)


def _by_offset(functions):
    return {function.offset: function for function in functions}


def _simple(count: int):
    methods = [_method(0x06000000 + index, "Ns.Sample", f"M{index}") for index in range(1, count + 1)]
    members = [_member("Ns.Sample", f"M{index}", f"code{index}") for index in range(1, count + 1)]
    return methods, members


def test_matching_and_overload_order(monkeypatch) -> None:
    methods = [
        _method(T1, "Ns.Outer", "Foo", params=1),
        _method(T2, "Ns.Outer", "Foo", params=1),
        _method(T3, "Ns.Outer", "Bar", params=2),
    ]
    members = [
        _member("Ns.Outer", "Foo", "foo-first", params=1),
        _member("Ns.Outer", "Foo", "foo-second", params=1),
        _member("Ns.Outer", "Bar", "bar", params=2),
    ]
    _install(monkeypatch, methods, members)

    functions = _by_offset(build_dotnet_functions("sample.exe", [], []))

    assert functions[hex(T1)].c_code == "foo-first"
    assert functions[hex(T2)].c_code == "foo-second"
    assert functions[hex(T3)].c_code == "bar"


def test_unmatched_method_gets_warning_when_kept_as_stub(monkeypatch) -> None:
    methods = [
        _method(T1, "Ns.Outer", "Run", callees=[T2]),
        _method(T2, "Ns.Outer", "Missing"),
    ]
    members = [_member("Ns.Outer", "Run", "run-body")]
    _install(monkeypatch, methods, members)

    stub = _by_offset(build_dotnet_functions("sample.exe", [], []))[hex(T2)]

    assert stub.c_code == ""
    assert stub.decompile_warnings == ["dotnet: no matching C# member"]


def test_returns_none_without_methods_with_body(monkeypatch) -> None:
    _install(monkeypatch, [_method(T1, "Ns.Outer", "Run", has_body=False)], [])
    assert build_dotnet_functions("sample.exe", [], []) is None


def test_returns_none_when_ilspy_fails(monkeypatch) -> None:
    _install(monkeypatch, [_method(T1, "Ns.Outer", "Run")], [], files=None)
    monkeypatch.setattr(df, "run_ilspy_project", lambda target, timeout: None)
    assert build_dotnet_functions("sample.exe", [], []) is None


def test_returns_none_when_no_method_matches(monkeypatch) -> None:
    methods = [_method(T1, "Ns.Outer", "Run")]
    members = [_member("Ns.Other", "Run", "other")]
    _install(monkeypatch, methods, members)
    assert build_dotnet_functions("sample.exe", [], []) is None


def test_generated_method_evidence_moves_to_parent(monkeypatch) -> None:
    parent = _method(T1, "Ns.Outer", "Run", callees=[T2])
    generated = _method(
        T2,
        "Ns.Outer+<Run>d__5",
        "MoveNext",
        generated=True,
        api_refs=["System.Net.WebClient::DownloadData"],
        strings=["prefix http://evil.example/payload suffix"],
    )
    members = [_member("Ns.Outer", "Run", "run-body")]
    hints = [{"offset": hex(T2), "rule": "download URL"}]
    findings = [Finding(source="floss", kind="url", value="http://evil.example/payload")]
    _install(monkeypatch, [parent, generated], members)

    functions = _by_offset(build_dotnet_functions("sample.exe", hints, findings))

    run = functions[hex(T1)]
    assert run.capa_hits == ["download URL"]
    assert run.iocs == ["http://evil.example/payload"]
    assert run.priority == df.CAPA_HIT_BONUS + df.IOC_REFERENCE_BONUS + df.DANGEROUS_API_BONUS
    generated_function = functions[hex(T2)]
    assert generated_function.is_library is True
    assert generated_function.priority == 0
    assert generated_function.c_code == ""
    assert generated_function.capa_hits == []


def test_capa_hint_accepts_both_offset_spellings(monkeypatch) -> None:
    methods = [_method(T2, "Ns.Outer", "Run")]
    members = [_member("Ns.Outer", "Run", "run-body")]
    hints = [
        {"offset": "0x6000002", "rule": "rule-a"},
        {"offset": "0x06000002", "rule": "rule-b"},
    ]
    _install(monkeypatch, methods, members)

    [function] = build_dotnet_functions("sample.exe", hints, [])

    assert function.capa_hits == ["rule-a", "rule-b"]
    assert function.priority == df.CAPA_HIT_BONUS


def test_ioc_substring_match_and_min_length(monkeypatch) -> None:
    methods = [_method(T1, "Ns.Outer", "Run", strings=["start http://evil.example/gate.php end", "abc"])]
    members = [_member("Ns.Outer", "Run", "run-body")]
    findings = [
        Finding(source="floss", kind="URL", value="http://evil.example/gate.php"),
        Finding(source="floss", kind="url", value="abc"),
    ]
    _install(monkeypatch, methods, members)

    [function] = build_dotnet_functions("sample.exe", [], findings)

    assert function.iocs == ["http://evil.example/gate.php"]
    assert function.priority == df.IOC_REFERENCE_BONUS


def test_dangerous_api_adds_bonus(monkeypatch) -> None:
    methods = [
        _method(T1, "Ns.Outer", "Run", api_refs=["System.Net.WebClient::DownloadData"]),
        _method(T2, "Ns.Outer", "Safe", api_refs=["System.Console::WriteLine"]),
    ]
    members = [
        _member("Ns.Outer", "Run", "run-body"),
        _member("Ns.Outer", "Safe", "safe-body"),
    ]
    _install(monkeypatch, methods, members)

    functions = _by_offset(build_dotnet_functions("sample.exe", [], []))

    assert "webclient::download" in DOTNET_DANGEROUS_APIS
    assert functions[hex(T1)].priority == df.DANGEROUS_API_BONUS
    assert functions[hex(T2)].priority == 0


def test_priority_propagates_to_callee(monkeypatch) -> None:
    methods = [
        _method(T1, "Ns.Outer", "Run", callees=[T2]),
        _method(T2, "Ns.Outer", "Payload"),
    ]
    members = [
        _member("Ns.Outer", "Run", "run-body"),
        _member("Ns.Outer", "Payload", "payload-body"),
    ]
    hints = [{"offset": hex(T1), "rule": "download URL"}]
    _install(monkeypatch, methods, members)

    functions = _by_offset(build_dotnet_functions("sample.exe", hints, []))

    assert functions[hex(T1)].priority == df.CAPA_HIT_BONUS
    assert functions[hex(T2)].priority == df.CAPA_HIT_BONUS - 1


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        ({"CROWBAR_DECOMPILE_MODE": "top", "CROWBAR_MAX_DECOMPILE": "2"}, 2),
        (
            {"CROWBAR_DECOMPILE_MODE": "auto", "CROWBAR_AUTO_ALL_CAP": "10", "CROWBAR_AUTO_TOP_N": "1"},
            5,
        ),
        (
            {"CROWBAR_DECOMPILE_MODE": "auto", "CROWBAR_AUTO_ALL_CAP": "2", "CROWBAR_AUTO_TOP_N": "2"},
            2,
        ),
        ({"CROWBAR_DECOMPILE_MODE": "all", "CROWBAR_MAX_DECOMPILE": "2"}, 5),
    ],
)
def test_selection_limits(monkeypatch, env, expected) -> None:
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    methods, members = _simple(5)
    _install(monkeypatch, methods, members)

    functions = build_dotnet_functions("sample.exe", [], [])

    assert len(functions) == expected


def test_evidence_is_selected_beyond_the_limit(monkeypatch) -> None:
    methods = [
        _method(T1, "Ns.Outer", "M1"),
        _method(T2, "Ns.Outer", "M2", strings=["http://evil.example/x"]),
        _method(T3, "Ns.Outer", "M3"),
        _method(T4, "Ns.Outer", "M4"),
    ]
    members = [_member("Ns.Outer", f"M{index}", f"code{index}") for index in range(1, 5)]
    hints = [{"offset": hex(T3), "rule": "download URL"}]
    findings = [Finding(source="floss", kind="url", value="http://evil.example/x")]
    monkeypatch.setenv("CROWBAR_MAX_DECOMPILE", "1")
    _install(monkeypatch, methods, members)

    functions = build_dotnet_functions("sample.exe", hints, findings)

    assert {function.offset for function in functions} == {hex(T2), hex(T3)}


def test_stubs_are_only_direct_callees(monkeypatch) -> None:
    methods = [
        _method(T1, "Ns.Outer", "Run", callees=[T2]),
        _method(T2, "Ns.Outer", "Helper"),
        _method(T3, "Ns.Outer", "Unrelated"),
    ]
    members = [
        _member("Ns.Outer", "Run", "run-body"),
        _member("Ns.Outer", "Helper", "helper-body"),
        _member("Ns.Outer", "Unrelated", "unrelated-body"),
    ]
    hints = [{"offset": hex(T1), "rule": "download URL"}]
    monkeypatch.setenv("CROWBAR_MAX_DECOMPILE", "1")
    _install(monkeypatch, methods, members)

    functions = _by_offset(build_dotnet_functions("sample.exe", hints, []))

    assert set(functions) == {hex(T1), hex(T2)}
    assert functions[hex(T2)].c_code == ""
    assert functions[hex(T2)].decompile_warnings == ["dotnet: not selected (budget)"]


def test_long_code_is_truncated(monkeypatch) -> None:
    methods = [_method(T1, "Ns.Outer", "Run")]
    members = [_member("Ns.Outer", "Run", "x" * (df.MAX_CODE_CHARS + 1))]
    _install(monkeypatch, methods, members)

    [function] = build_dotnet_functions("sample.exe", [], [])

    assert len(function.c_code) == df.MAX_CODE_CHARS
    assert "dotnet: code truncated" in function.decompile_warnings


def test_callees_and_xrefs_are_hex_offsets(monkeypatch) -> None:
    methods = [
        _method(T1, "Ns.Outer", "Run", callees=[T2, 0x06999999]),
        _method(T2, "Ns.Outer", "Helper", callees=[T1]),
    ]
    members = [
        _member("Ns.Outer", "Run", "run-body"),
        _member("Ns.Outer", "Helper", "helper-body"),
    ]
    _install(monkeypatch, methods, members)

    functions = _by_offset(build_dotnet_functions("sample.exe", [], []))

    assert functions[hex(T1)].callees == [hex(T2)]
    assert functions[hex(T1)].xrefs == [hex(T2)]
    assert functions[hex(T2)].xrefs == [hex(T1)]


def test_must_include_is_capped(monkeypatch):
    import analyzers.dotnet_functions as df
    monkeypatch.setattr(df, "MAX_MUST_INCLUDE_EXTRA", 2)
    monkeypatch.setenv("CROWBAR_DECOMPILE_MODE", "top")
    monkeypatch.setenv("CROWBAR_MAX_DECOMPILE", "1")
    methods = [df.DotnetMethod(token=0x06000001 + i, type_name="Ns.T", name=f"M{i}", param_count=0,
                               il_size=10, has_body=True) for i in range(6)]
    members = [df.CSharpMember(type_name="Ns.T", name=f"M{i}", param_count=0, code=f"void M{i}() {{}}",
                               file="T.cs", start_line=1) for i in range(6)]
    hints = [{"offset": hex(m.token), "rule": "r"} for m in methods]
    monkeypatch.setattr(df, "extract_dotnet_methods", lambda path: methods)
    monkeypatch.setattr(df, "run_ilspy_project", lambda path, timeout: {"T.cs": "x"})
    monkeypatch.setattr(df, "split_csharp_members", lambda files: members)
    out = df.build_dotnet_functions("x.dll", hints, [])
    assert sum(1 for f in out if f.c_code) == 3

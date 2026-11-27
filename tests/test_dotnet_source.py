"""Tests for analyzers.dotnet_source (synthetic C# only)."""

from __future__ import annotations

import os
import subprocess

import pytest

from analyzers import dotnet_source
from analyzers.dotnet_source import CSharpMember, run_ilspy_project, split_csharp_members

EXAMPLE = r'''using System.IO;
using System.Text;

namespace Sample.Util;

internal static class Encoder
{
	private sealed class Buffer
	{
		private int _count;

		internal Buffer(int size, Encoding enc)
		{
			_count = size;
		}

		internal void Add(char ch)
		{
			if (_count > 0)
			{
				Flush("}{ not a brace");
			}
		}

		public int Count => _count;
	}

	public static string Name { get; set; }

	public int this[int i]
	{
		get
		{
			return i;
		}
		set
		{
			_ = value;
		}
	}

	static Encoder()
	{
	}

	private static void Run<T>(List<T> items, Dictionary<string, int> map, int x = 3)
	{
		// comment with { brace
		string s = @"verbatim ""}"" text";
		char c = '{';
	}
}
'''


def _by_key(members: list[CSharpMember]) -> dict[tuple[str, str, int], CSharpMember]:
    return {(m.type_name, m.name, m.param_count): m for m in members}


def _names(members: list[CSharpMember]) -> set[str]:
    return {m.name for m in members}


def test_example_members_and_metadata_names() -> None:
    members = split_csharp_members({"Sample/Util/Encoder.cs": EXAMPLE})
    found = _by_key(members)

    assert set(found) == {
        ("Sample.Util.Encoder+Buffer", ".ctor", 2),
        ("Sample.Util.Encoder+Buffer", "Add", 1),
        ("Sample.Util.Encoder+Buffer", "get_Count", 0),
        ("Sample.Util.Encoder", "get_Item", 1),
        ("Sample.Util.Encoder", "set_Item", 2),
        ("Sample.Util.Encoder", ".cctor", 0),
        ("Sample.Util.Encoder", "Run", 3),
    }
    # The auto-property "Name" has no accessor bodies and is skipped.
    assert "get_Name" not in _names(members)
    assert "set_Name" not in _names(members)
    assert len(members) == 7
    assert {m.file for m in members} == {"Sample/Util/Encoder.cs"}


def test_example_code_is_full_and_dedented() -> None:
    members = split_csharp_members({"Sample/Util/Encoder.cs": EXAMPLE})
    run = _by_key(members)[("Sample.Util.Encoder", "Run", 3)]

    assert run.code.startswith(
        "private static void Run<T>(List<T> items, Dictionary<string, int> map, int x = 3)\n{\n"
    )
    assert "\n\t// comment with { brace" in run.code
    assert 'string s = @"verbatim ""}"" text";' in run.code
    assert "char c = '{';" in run.code
    assert run.code.endswith("\n}")
    assert "static Encoder" not in run.code
    assert run.start_line == EXAMPLE[: EXAMPLE.index("private static void Run")].count("\n") + 1

    add = _by_key(members)[("Sample.Util.Encoder+Buffer", "Add", 1)]
    assert add.code.startswith("internal void Add(char ch)\n{\n")
    assert 'Flush("}{ not a brace");' in add.code
    assert add.start_line == EXAMPLE[: EXAMPLE.index("internal void Add")].count("\n") + 1


def test_generic_type_parameters_removed_from_type_name() -> None:
    source = """
namespace N;

internal class Box<T>
{
	internal class Node<U>
	{
		internal void Add(U value)
		{
		}
	}

	internal void Put(T item)
	{
	}

	public int Count => 0;
}
"""
    members = split_csharp_members({"N/Box.cs": source})
    found = _by_key(members)

    assert set(found) == {
        ("N.Box+Node", "Add", 1),
        ("N.Box", "Put", 1),
        ("N.Box", "get_Count", 0),
    }


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("namespace A.B;\ninternal class C\n{\n\tvoid M()\n\t{\n\t}\n}\n", "A.B.C"),
        ("namespace A.B\n{\n\tinternal class C\n\t{\n\t\tvoid M()\n\t\t{\n\t\t}\n\t}\n}\n", "A.B.C"),
        ("internal class C\n{\n\tvoid M()\n\t{\n\t}\n}\n", "C"),
        (
            "namespace A\n{\n\tnamespace B\n\t{\n\t\tinternal class C\n\t\t{\n\t\t\tvoid M()\n\t\t\t{\n\t\t\t}\n\t\t}\n\t}\n}\n",
            "A.B.C",
        ),
    ],
)
def test_namespace_forms(source: str, expected: str) -> None:
    members = split_csharp_members({"C.cs": source})
    assert len(members) == 1
    assert members[0].type_name == expected
    assert members[0].name == "M"


def test_braces_in_literals_and_comments_do_not_break_structure() -> None:
    source = r'''
internal class Braces
{
	private void A()
	{
		// closing brace } and opening {
		/* block } { comment */
		string s = "a } { b \" c";
		string v = @"verbatim ""}"" text {";
		string i = $"value {(1 + 2)} }} {{";
		string vi = $@"path {s} ""}}""";
		string raw = """raw } { text""";
		char c1 = '{';
		char c2 = '\'';
		char c3 = '}';
	}

	private void B()
	{
	}

	public int Value => 7;
}
'''
    members = split_csharp_members({"Braces.cs": source})
    found = _by_key(members)

    assert set(found) == {
        ("Braces", "A", 0),
        ("Braces", "B", 0),
        ("Braces", "get_Value", 0),
    }
    a = found[("Braces", "A", 0)]
    for fragment in (
        '// closing brace } and opening {',
        '/* block } { comment */',
        'string s = "a } { b \\" c";',
        'string v = @"verbatim ""}"" text {";',
        'string i = $"value {(1 + 2)} }} {{";',
        'string vi = $@"path {s} ""}}""";',
        'string raw = """raw } { text""";',
        "char c1 = '{';",
        "char c2 = '\\'';",
        "char c3 = '}';",
    ):
        assert fragment in a.code
    assert found[("Braces", "B", 0)].code == "private void B()\n{\n}"


def test_parameter_counting_with_generics_defaults_and_literals() -> None:
    source = '''
internal class Params
{
	internal void Generic(List<Dictionary<string, int>> map, int a = 3)
	{
	}

	internal void Defaults(string sep = ",", char brace = '{', int[] xs = null, params object[] rest)
	{
	}

	internal void Nested(Action<int, int> callback, (int, string) pair = default)
	{
	}

	internal void NoArgs()
	{
	}
}
'''
    found = {(m.type_name, m.name): m for m in split_csharp_members({"Params.cs": source})}

    assert found[("Params", "Generic")].param_count == 2
    assert found[("Params", "Defaults")].param_count == 4
    assert found[("Params", "Nested")].param_count == 2
    assert found[("Params", "NoArgs")].param_count == 0


def test_operators() -> None:
    source = '''
internal class Ops
{
	public static Ops operator +(Ops a, Ops b) { return a; }
	public static Ops operator -(Ops a, Ops b) { return a; }
	public static bool operator ==(Ops a, Ops b) { return true; }
	public static bool operator !=(Ops a, Ops b) { return false; }
	public static bool operator %(Ops a, Ops b) { return false; }
	public static implicit operator string(Ops o) { return ""; }
	public static explicit operator Ops(int value) { return new Ops(); }
}
'''
    found = _by_key(split_csharp_members({"Ops.cs": source}))

    assert set(found) == {
        ("Ops", "op_Addition", 2),
        ("Ops", "op_Subtraction", 2),
        ("Ops", "op_Equality", 2),
        ("Ops", "op_Inequality", 2),
        ("Ops", "op_Unknown", 2),
        ("Ops", "op_Implicit", 1),
        ("Ops", "op_Explicit", 1),
    }


def test_property_accessors_indexer_event_and_skips() -> None:
    source = '''
internal class Members
{
	private int _v;

	public int Value
	{
		get
		{
			return _v;
		}
		init
		{
			_v = value;
		}
	}

	public string Name { get; set; }

	public int Auto { get; set; } = 3;

	public int Expr => _v;

	public int Arrow
	{
		get => _v;
		set => _v = value;
	}

	public int this[int a, int b] => a + b;

	public int this[int i]
	{
		get { return i; }
		set { _ = value; }
	}

	public event EventHandler Changed
	{
		add { }
		remove { }
	}

	public event EventHandler NoBody;
}
'''
    members = split_csharp_members({"Members.cs": source})
    found = _by_key(members)

    assert set(found) == {
        ("Members", "get_Value", 0),
        ("Members", "set_Value", 1),
        ("Members", "get_Expr", 0),
        ("Members", "get_Arrow", 0),
        ("Members", "set_Arrow", 1),
        ("Members", "get_Item", 2),
        ("Members", "get_Item", 1),
        ("Members", "set_Item", 2),
        ("Members", "add_Changed", 1),
        ("Members", "remove_Changed", 1),
    }
    # Fields, auto-properties and bodyless event fields produce no members.
    assert "_v" not in _names(members)
    assert "Name" not in _names(members)
    assert "Auto" not in _names(members)
    assert "NoBody" not in _names(members)

    getter = found[("Members", "get_Value", 0)]
    assert getter.code.startswith("get\n{\n")
    assert "return _v;" in getter.code
    assert "init" not in getter.code


def test_struct_interface_record_and_record_struct() -> None:
    source = '''
internal struct S
{
	internal void M()
	{
	}
}

internal interface I
{
	void N();
}

internal record R(int X)
{
	internal void P()
	{
	}
}

internal record struct RS(int Y)
{
	internal void Q()
	{
	}
}
'''
    found = _by_key(split_csharp_members({"Kinds.cs": source}))

    assert set(found) == {
        ("S", "M", 0),
        ("R", "P", 0),
        ("RS", "Q", 0),
    }


def test_constructors_destructor_explicit_interface_and_expression_bodies() -> None:
    source = '''
internal sealed class Ctor : IFoo
{
	static Ctor()
	{
	}

	public Ctor(int x) : base()
	{
	}

	~Ctor()
	{
	}

	void IFoo.Bar()
	{
	}

	int IFoo.Count => 0;

	internal T Echo<T>(T value) => value;
}
'''
    found = _by_key(split_csharp_members({"Ctor.cs": source}))

    assert set(found) == {
        ("Ctor", ".cctor", 0),
        ("Ctor", ".ctor", 1),
        ("Ctor", "Finalize", 0),
        ("Ctor", "Bar", 0),
        ("Ctor", "get_Count", 0),
        ("Ctor", "Echo", 1),
    }
    assert found[("Ctor", "Echo", 1)].code == "internal T Echo<T>(T value) => value;"


def test_interface_members_without_bodies_are_skipped() -> None:
    source = '''
internal interface IFoo
{
	void M(int a);
	int P { get; }
	event EventHandler E;
}

internal class Impl : IFoo
{
	public void M(int a)
	{
	}

	public int P { get { return 0; } }
}
'''
    found = _by_key(split_csharp_members({"Impl.cs": source}))

    assert set(found) == {("Impl", "M", 1), ("Impl", "get_P", 0)}


def test_attributes_are_part_of_code_and_start_line() -> None:
    source = '''
internal class Attr
{
	[Obsolete("do not use")]
	private void M()
	{
	}
}
'''
    members = split_csharp_members({"Attr.cs": source})
    assert len(members) == 1
    member = members[0]
    assert member.code.startswith('[Obsolete("do not use")]\nprivate void M()')
    assert member.start_line == source[: source.index("[Obsolete")].count("\n") + 1


def test_preprocessor_directives_are_ignored() -> None:
    source = (
        "#nullable disable\n"
        "namespace N;\n"
        "#pragma warning disable CS0618\n"
        "internal class C\n"
        "{\n"
        "\tvoid M()\n"
        "\t{\n"
        "\t}\n"
        "}\n"
    )
    members = split_csharp_members({"C.cs": source})
    assert len(members) == 1
    assert (members[0].type_name, members[0].name) == ("N.C", "M")


def test_unbalanced_source_does_not_raise() -> None:
    source = "internal class Broken {\n\tvoid M()\n\t{\n\t\tif (true) {\n"
    assert isinstance(split_csharp_members({"Broken.cs": source}), list)


def test_non_string_payload_is_ignored() -> None:
    assert split_csharp_members({"bad.cs": None}) == []  # type: ignore[dict-item]


def test_run_ilspy_project_collects_cs_files_and_cleans_up(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_run_tool(cmd: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
        captured["cmd"] = cmd
        captured["timeout"] = timeout
        output_dir = cmd[3]
        os.makedirs(os.path.join(output_dir, "Ns"), exist_ok=True)
        with open(os.path.join(output_dir, "Ns", "Foo.cs"), "w", encoding="utf-8") as handle:
            handle.write("internal class Foo\n{\n}\n")
        with open(os.path.join(output_dir, "Ns", "notes.txt"), "w", encoding="utf-8") as handle:
            handle.write("not C#")
        with open(os.path.join(output_dir, "Ns", "AssemblyInfo.cs"), "w", encoding="utf-8") as handle:
            handle.write("// metadata\n")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(dotnet_source, "_run_tool", fake_run_tool)
    result = run_ilspy_project("sample.exe", 42)

    assert result == {
        "Ns/Foo.cs": "internal class Foo\n{\n}\n",
        "Ns/AssemblyInfo.cs": "// metadata\n",
    }
    assert captured["timeout"] == 42
    cmd = captured["cmd"]
    assert isinstance(cmd, list)
    assert cmd[:4] == ["ilspycmd", "-p", "-o", cmd[3]]
    assert cmd[4] == "sample.exe"
    assert not os.path.exists(cmd[3])


def test_run_ilspy_project_returns_none_on_tool_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, str] = {}

    def fake_run_tool(cmd: list[str], timeout: int) -> None:
        captured["dir"] = cmd[3]
        return None

    monkeypatch.setattr(dotnet_source, "_run_tool", fake_run_tool)
    assert run_ilspy_project("sample.exe", 5) is None
    assert not os.path.exists(captured["dir"])


def test_run_ilspy_project_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run_tool(cmd: list[str], timeout: int) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(dotnet_source, "_run_tool", fake_run_tool)
    assert run_ilspy_project("sample.exe", 5) is None


def test_run_ilspy_project_skips_large_files_and_stops_at_total_limit(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(dotnet_source, "MAX_SOURCE_FILE_BYTES", 10)
    monkeypatch.setattr(dotnet_source, "MAX_TOTAL_SOURCE_BYTES", 12)

    def fake_run_tool(cmd: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
        output_dir = cmd[3]
        for name, payload in (("a.cs", "12345678"), ("b.cs", "12345678"), ("c.cs", "12345678")):
            with open(os.path.join(output_dir, name), "w", encoding="utf-8") as handle:
                handle.write(payload)
        with open(os.path.join(output_dir, "0huge.cs"), "w", encoding="utf-8") as handle:
            handle.write("0123456789ABC")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(dotnet_source, "_run_tool", fake_run_tool)
    with caplog.at_level("WARNING"):
        result = run_ilspy_project("sample.exe", 5)

    # huge.cs is skipped; a.cs fits, b.cs exceeds the remaining total, so reading stops.
    assert result == {"a.cs": "12345678"}
    assert "per-file limit" in caplog.text
    assert "source limit" in caplog.text

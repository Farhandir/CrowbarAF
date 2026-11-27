"""Tests for analyzers.dotnet_methods (no real assemblies are used)."""

from __future__ import annotations

import logging
from types import SimpleNamespace

from dncil.clr.token import StringToken, Token

from analyzers import dotnet_methods
from analyzers.dotnet_methods import (
    DotnetMethod,
    _analyze_method,
    _build_typedef_names,
    _extract_from_tables,
    _resolve_call_token,
    extract_dotnet_methods,
)


class FakeIndex:
    """Minimal stand-in for dnfile's MDTableIndex / CodedIndex."""

    def __init__(self, row=None, row_index: int = 0, table=None):
        self.row = row
        self.row_index = row_index
        self.table = table


def fake_table(name: str, number: int):
    return SimpleNamespace(name=name, number=number)


def fake_flags(**overrides):
    values = {"mdAbstract": False, "miRuntime": False, "miInternalCall": False}
    values.update(overrides)
    return SimpleNamespace(**values)


def fake_method(
    name: str = "Main",
    rva: int = 0x100,
    params: list | None = None,
    abstract: bool = False,
):
    return SimpleNamespace(
        Name=name,
        Rva=rva,
        ParamList=params or [],
        Flags=fake_flags(mdAbstract=abstract),
        ImplFlags=fake_flags(),
    )


def fake_typedef(name: str, namespace: str = "", methods: list[int] | None = None):
    return SimpleNamespace(
        TypeName=name,
        TypeNamespace=namespace,
        MethodList=[FakeIndex(row_index=rid) for rid in (methods or [])],
    )


def fake_body(*instructions, code_size: int | None = 12):
    fields = {"instructions": list(instructions)}
    if code_size is not None:
        fields["code_size"] = code_size
    return SimpleNamespace(**fields)


def call_instruction(token: int):
    return SimpleNamespace(opcode=dotnet_methods.OpCodes.Call, operand=Token(token))


def ldstr_instruction(rid: int):
    return SimpleNamespace(opcode=dotnet_methods.OpCodes.Ldstr, operand=StringToken(rid))


def memberref(name: str, parent_table: str, parent_row=None):
    return SimpleNamespace(
        Name=name,
        Class=FakeIndex(
            row=parent_row,
            row_index=1,
            table=fake_table(parent_table, 1),
        ),
    )


def run_core(methods, typedefs, *, tables=None, body_loader=None, nested=None, impl_map=None,
             user_strings=None, max_methods=20000):
    return _extract_from_tables(
        method_rows=methods,
        typedef_rows=typedefs,
        nested_rows=nested or [],
        impl_map_rows=impl_map or [],
        tables=tables or {},
        user_strings=user_strings,
        body_loader=body_loader,
        max_methods=max_methods,
    )


def test_nested_type_names_and_generic_arity():
    typedefs = [
        fake_typedef("Outer", "Ns"),
        fake_typedef("Inner", ""),
        fake_typedef("List`1", "Ns"),
    ]
    nested = [
        SimpleNamespace(
            NestedClass=FakeIndex(row_index=2),
            EnclosingClass=FakeIndex(row_index=1),
        )
    ]

    names = _build_typedef_names(typedefs, nested)

    assert names[1] == "Ns.Outer"
    assert names[2] == "Ns.Outer+Inner"
    assert names[3] == "Ns.List"


def test_nested_type_without_namespace():
    typedefs = [fake_typedef("Outer"), fake_typedef("Inner")]
    nested = [
        SimpleNamespace(
            NestedClass=FakeIndex(row_index=2),
            EnclosingClass=FakeIndex(row_index=1),
        )
    ]

    assert _build_typedef_names(typedefs, nested)[2] == "Outer+Inner"


def test_param_count_ignores_return_and_populates_fields():
    params = [
        FakeIndex(row=SimpleNamespace(Sequence=0)),  # return value
        FakeIndex(row=SimpleNamespace(Sequence=1)),
        FakeIndex(row=SimpleNamespace(Sequence=2)),
    ]
    methods = [fake_method("Main", params=params)]
    typedefs = [fake_typedef("Program", "Ns", methods=[1])]
    body = fake_body(call_instruction(0x06000002), code_size=7)

    result = run_core(
        methods,
        typedefs,
        body_loader=lambda row: body,
    )

    assert len(result) == 1
    method = result[0]
    assert method.token == 0x06000001
    assert method.type_name == "Ns.Program"
    assert method.name == "Main"
    assert method.param_count == 2
    assert method.il_size == 7
    assert method.has_body is True
    assert method.full_name == "Ns.Program::Main"


def test_callees_are_deduped_and_keep_order():
    methods = [
        fake_method("A"),
        fake_method("B"),
        fake_method("C"),
    ]
    typedefs = [fake_typedef("T", "Ns", methods=[1, 2, 3])]
    body = fake_body(
        call_instruction(0x06000002),
        call_instruction(0x06000003),
        SimpleNamespace(opcode=dotnet_methods.OpCodes.Callvirt, operand=Token(0x06000002)),
        SimpleNamespace(opcode=dotnet_methods.OpCodes.Newobj, operand=Token(0x06000003)),
    )

    result = run_core(methods, typedefs, body_loader=lambda row: body)

    assert result[0].callees == [0x06000002, 0x06000003]


def test_memberref_resolves_to_api_string_and_strips_arity():
    memberref_row = memberref(
        "Open",
        "TypeRef",
        SimpleNamespace(TypeName="File`1", TypeNamespace="System.IO", ResolutionScope=None),
    )
    tables = {10: [memberref_row]}
    body = fake_body(call_instruction(0x0A000001))

    result = run_core(
        [fake_method()],
        [fake_typedef("T", "Ns", methods=[1])],
        tables=tables,
        body_loader=lambda row: body,
    )

    assert result[0].callees == []
    assert result[0].api_refs == ["System.IO.File::Open"]


def test_nested_typeref_resolution_for_memberref():
    outer = SimpleNamespace(
        TypeName="Outer`1",
        TypeNamespace="Ns",
        ResolutionScope=None,
    )
    inner = SimpleNamespace(
        TypeName="Inner",
        TypeNamespace="",
        ResolutionScope=FakeIndex(row_index=1, table=fake_table("TypeRef", 1)),
    )
    memberref_row = memberref("Run", "TypeRef", inner)
    tables = {1: [outer], 10: [memberref_row]}

    _, api = _resolve_call_token(Token(0x0A000001), tables, {})

    assert api == "Ns.Outer+Inner::Run"


def test_typespec_memberref_is_unresolved():
    memberref_row = memberref("Invoke", "TypeSpec", SimpleNamespace(Signature=b""))
    tables = {10: [memberref_row]}

    callee, api = _resolve_call_token(Token(0x0A000001), tables, {})

    assert callee is None
    assert api == "?::Invoke"


def test_methodspec_resolves_to_methoddef():
    method_spec = SimpleNamespace(
        Method=FakeIndex(row_index=2, table=fake_table("MethodDef", 6)),
    )
    tables = {43: [method_spec]}

    callee, api = _resolve_call_token(Token(0x2B000001), tables, {})

    assert callee == 2
    assert api is None


def test_methodspec_resolves_to_memberref():
    memberref_row = memberref(
        "WriteLine",
        "TypeRef",
        SimpleNamespace(TypeName="Console", TypeNamespace="System", ResolutionScope=None),
    )
    method_spec = SimpleNamespace(
        Method=FakeIndex(row_index=1, table=fake_table("MemberRef", 10)),
    )
    tables = {10: [memberref_row], 43: [method_spec]}

    callee, api = _resolve_call_token(Token(0x2B000001), tables, {})

    assert callee is None
    assert api == "System.Console::WriteLine"


def test_pinvoke_method_call_adds_module_import():
    method = fake_method("Native")
    impl_map = [
        SimpleNamespace(
            MemberForwarded=FakeIndex(row_index=2, table=fake_table("MethodDef", 6)),
            ImportName="VirtualAlloc",
            ImportScope=FakeIndex(row=SimpleNamespace(Name="kernel32.dll")),
        )
    ]
    body = fake_body(call_instruction(0x06000002))

    result = run_core(
        [fake_method("Caller"), method],
        [fake_typedef("T", "Ns", methods=[1, 2])],
        impl_map=impl_map,
        body_loader=lambda row: body if row is not None and row.Name == "Caller" else None,
    )

    assert result[0].callees == [0x06000002]
    assert result[0].api_refs == ["kernel32.dll!VirtualAlloc"]


def test_ldstr_strings_are_deduped_and_invalid_are_skipped():
    class FakeUserStrings:
        def get(self, rid):
            if rid == 1:
                return SimpleNamespace(value="hello")
            if rid == 2:
                raise UnicodeDecodeError("utf-16", b"\xff", 0, 1, "bad")
            return None

    body = fake_body(
        ldstr_instruction(1),
        ldstr_instruction(1),
        ldstr_instruction(2),
        ldstr_instruction(3),
    )

    result = run_core(
        [fake_method()],
        [fake_typedef("T", "Ns", methods=[1])],
        user_strings=FakeUserStrings(),
        body_loader=lambda row: body,
    )

    assert result[0].strings == ["hello"]


def test_ldstr_string_is_truncated():
    class FakeUserStrings:
        def get(self, rid):
            return SimpleNamespace(value="x" * 600)

    body = fake_body(ldstr_instruction(1))
    result = run_core(
        [fake_method()],
        [fake_typedef("T", "Ns", methods=[1])],
        user_strings=FakeUserStrings(),
        body_loader=lambda row: body,
    )

    assert len(result[0].strings[0]) == 500


def test_is_generated_from_method_name_and_enclosing_type():
    generated_method = fake_method("<Main>b__0_0")
    generated_type = fake_method("Run")

    result = run_core(
        [generated_method, generated_type],
        [fake_typedef("T", "Ns", methods=[1]), fake_typedef("<>c", "Ns", methods=[2])],
    )

    assert result[0].is_generated is True
    assert result[1].is_generated is True


def test_body_parse_error_keeps_method_record():
    def broken_body_loader(row):
        raise ValueError("broken body")

    result = run_core(
        [fake_method()],
        [fake_typedef("T", "Ns", methods=[1])],
        body_loader=broken_body_loader,
    )

    assert len(result) == 1
    assert result[0].has_body is False
    assert result[0].il_size == 0
    assert result[0].full_name == "Ns.T::Main"


def test_abstract_method_body_loader_is_not_called():
    def forbidden_body_loader(row):
        raise AssertionError("abstract methods must not be parsed")

    result = run_core(
        [fake_method(abstract=True)],
        [fake_typedef("T", "Ns", methods=[1])],
        body_loader=forbidden_body_loader,
    )

    assert result[0].has_body is False


def test_il_size_falls_back_to_instruction_sizes():
    instruction = SimpleNamespace(
        opcode=dotnet_methods.OpCodes.Nop,
        operand=None,
        size=1,
    )
    body = fake_body(instruction, code_size=None)

    result = run_core(
        [fake_method()],
        [fake_typedef("T", "Ns", methods=[1])],
        body_loader=lambda row: body,
    )

    assert result[0].il_size == 1


def test_method_limit_logs_and_truncates(caplog):
    methods = [fake_method(f"M{i}") for i in range(3)]
    typedefs = [fake_typedef("T", "Ns", methods=[1, 2, 3])]

    with caplog.at_level(logging.WARNING, logger=dotnet_methods.__name__):
        result = run_core(methods, typedefs, max_methods=2)

    assert [method.name for method in result] == ["M0", "M1"]
    assert "method limit" in caplog.text


def test_full_name_property():
    method = DotnetMethod(
        token=0x06000001,
        type_name="Ns.Outer+Inner",
        name="Run",
        param_count=0,
        il_size=0,
    )

    assert method.full_name == "Ns.Outer+Inner::Run"


def test_extract_returns_empty_when_dnpe_raises(monkeypatch):
    def broken_dnpe(path):
        raise ValueError("not a PE")

    monkeypatch.setattr(dotnet_methods.dnfile, "dnPE", broken_dnpe)

    assert extract_dotnet_methods("not-a-sample") == []


def test_extract_returns_empty_without_net_and_closes(monkeypatch):
    closed = []

    class FakePE:
        net = None

        def close(self):
            closed.append(True)

    monkeypatch.setattr(dotnet_methods.dnfile, "dnPE", lambda path: FakePE())

    assert extract_dotnet_methods("not-dotnet") == []
    assert closed == [True]


def test_extract_returns_empty_without_methoddef_table(monkeypatch):
    closed = []

    class FakePE:
        net = SimpleNamespace(mdtables=SimpleNamespace(tables={2: []}))

        def close(self):
            closed.append(True)

    monkeypatch.setattr(dotnet_methods.dnfile, "dnPE", lambda path: FakePE())

    assert extract_dotnet_methods("not-dotnet") == []
    assert closed == [True]


def test_extract_wires_tables_user_strings_and_body_loader(monkeypatch):
    closed = []
    user_strings = SimpleNamespace(get=lambda rid: SimpleNamespace(value="hi"))
    method = fake_method("Main")
    typedef = fake_typedef("T", "Ns", methods=[1])
    body = fake_body(ldstr_instruction(1), code_size=5)

    class FakePE:
        net = SimpleNamespace(
            mdtables=SimpleNamespace(
                tables={
                    2: [typedef],
                    6: [method],
                    41: [],
                    28: [],
                }
            ),
            user_strings=user_strings,
        )

        def close(self):
            closed.append(True)

    monkeypatch.setattr(dotnet_methods.dnfile, "dnPE", lambda path: FakePE())
    monkeypatch.setattr(dotnet_methods, "_read_method_body", lambda pe, row: body)

    result = extract_dotnet_methods("fake.dll")

    assert len(result) == 1
    assert result[0].type_name == "Ns.T"
    assert result[0].has_body is True
    assert result[0].strings == ["hi"]
    assert closed == [True]


def test_analyze_method_does_not_raise_on_broken_instruction():
    broken = SimpleNamespace(opcode=dotnet_methods.OpCodes.Call, operand=None)
    body = fake_body(broken)

    method = _analyze_method(
        fake_method(),
        0x06000001,
        "Ns.T",
        {},
        None,
        {},
        body,
    )

    assert method.callees == []
    assert method.has_body is True

"""db.py, db_writer_node ve graph bağlantısı için testler."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing

import pytest

import db
import nodes
from graph import build_graph
from state import AgentState, DecompiledFunction, Finding, SampleInfo

SHA = "a" * 64


def _rows(path, sql, args=()):
    with closing(sqlite3.connect(path)) as conn:
        return conn.execute(sql, args).fetchall()


def _fn(offset, callees=(), warnings=(), code="int f(){}", name="f", priority=5):
    return DecompiledFunction(
        offset=offset, name=name, priority=priority, c_code=code, callees=list(callees),
        decompile_warnings=list(warnings),
    )


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test.db")


class TestInitDb:
    def test_creates_all_tables_with_spec_columns(self, db_path) -> None:
        assert db.init_db(db_path) == db_path
        tables = {r[0] for r in _rows(db_path, "SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"samples", "findings", "functions", "calls"} <= tables

        def cols(table):
            return [r[1] for r in _rows(db_path, f"PRAGMA table_info({table})")]

        assert cols("samples") == ["sha256", "file_type", "route", "packer", "arch"]
        assert cols("findings") == ["id", "sha256", "source", "kind", "value", "address", "confidence"]
        assert cols("functions") == [
            "id", "sha256", "offset", "name", "priority", "c_code", "decompile_warnings",
            "llm_summary", "size", "is_library", "capa_hits", "xrefs",
        ]
        assert cols("calls") == ["id", "sha256", "caller_offset", "callee_offset"]

    def test_is_idempotent_and_keeps_data(self, db_path) -> None:
        db.init_db(db_path)
        db.insert_sample(SampleInfo(sha256=SHA), db_path)
        db.init_db(db_path)
        assert len(_rows(db_path, "SELECT * FROM samples")) == 1

    def test_default_path_is_crowbaraf_db(self) -> None:
        assert db.DEFAULT_DB_PATH.endswith("crowbaraf.db") or "CROWBAR_DB_PATH" in __import__("os").environ


class TestInsertSample:
    def test_insert_and_replace(self, db_path) -> None:
        db.init_db(db_path)
        db.insert_sample(SampleInfo(sha256=SHA, file_type="PE", route="native", packer="UPX", arch="x86-64"), db_path)
        db.insert_sample(SampleInfo(sha256=SHA, file_type="PE", route="python", packer="none", arch="x86-64"), db_path)
        assert _rows(db_path, "SELECT * FROM samples") == [(SHA, "PE", "python", "none", "x86-64")]


class TestInsertFindings:
    def test_insert_and_reanalysis_replaces(self, db_path) -> None:
        db.init_db(db_path)
        f1 = Finding(source="capa", kind="rule", value="r", address="0x401000", confidence=0.9)
        f2 = Finding(source="yara", kind="rule", value="Emotet")
        assert db.insert_findings(SHA, [f1, f2], db_path) == 2
        assert db.insert_findings(SHA, [f2], db_path) == 1  # yeniden analiz: eskiler silinir
        rows = _rows(db_path, "SELECT sha256, source, kind, value, address, confidence FROM findings")
        assert rows == [(SHA, "yara", "rule", "Emotet", "", 1.0)]

    def test_other_samples_untouched(self, db_path) -> None:
        db.init_db(db_path)
        db.insert_findings("other", [Finding(source="s", kind="k", value="v")], db_path)
        db.insert_findings(SHA, [], db_path)
        assert len(_rows(db_path, "SELECT * FROM findings WHERE sha256 = 'other'")) == 1

    def test_empty(self, db_path) -> None:
        db.init_db(db_path)
        assert db.insert_findings(SHA, [], db_path) == 0


class TestInsertFunctionsAndCalls:
    def test_functions_and_call_edges(self, db_path) -> None:
        db.init_db(db_path)
        fns = [
            _fn("0x1", callees=["0x2", "0x3", "0x2"], warnings=["warn ü"]),  # tekrar eden çağrı tek satır
            _fn("0x2", name="g"),
        ]
        assert db.insert_functions_and_calls(SHA, fns, db_path) == (2, 2)

        funcs = _rows(db_path, "SELECT offset, name, priority, c_code, decompile_warnings FROM functions ORDER BY id")
        assert funcs[0][:4] == ("0x1", "f", 5, "int f(){}")
        assert json.loads(funcs[0][4]) == ["warn ü"]
        assert json.loads(funcs[1][4]) == []
        calls = _rows(db_path, "SELECT sha256, caller_offset, callee_offset FROM calls ORDER BY id")
        assert calls == [(SHA, "0x1", "0x2"), (SHA, "0x1", "0x3")]  # 0x3 functions tablosunda olmasa da yazılır

    def test_reanalysis_replaces_both_tables(self, db_path) -> None:
        db.init_db(db_path)
        db.insert_functions_and_calls(SHA, [_fn("0x1", callees=["0x2"])], db_path)
        db.insert_functions_and_calls(SHA, [_fn("0x9")], db_path)
        assert _rows(db_path, "SELECT offset FROM functions") == [("0x9",)]
        assert _rows(db_path, "SELECT * FROM calls") == []

    def test_empty(self, db_path) -> None:
        db.init_db(db_path)
        assert db.insert_functions_and_calls(SHA, [], db_path) == (0, 0)


class TestDbWriterNode:
    @pytest.fixture(autouse=True)
    def _isolate_db(self, db_path, monkeypatch):
        monkeypatch.setattr(db, "DEFAULT_DB_PATH", db_path)

    def test_writes_everything_and_returns_empty(self, db_path) -> None:
        state = AgentState(
            file_path="x",
            sample=SampleInfo(sha256=SHA, file_type="PE", route="native", packer="none", arch="x86"),
            findings=[Finding(source="capa", kind="rule", value="r")],
            source_code=[_fn("0x1", callees=["0x2"]), _fn("0x2")],
        )
        assert nodes.db_writer_node(state) == {}
        assert _rows(db_path, "SELECT sha256, route FROM samples") == [(SHA, "native")]
        assert len(_rows(db_path, "SELECT * FROM findings")) == 1
        assert len(_rows(db_path, "SELECT * FROM functions")) == 2
        assert _rows(db_path, "SELECT caller_offset, callee_offset FROM calls") == [("0x1", "0x2")]

    def test_empty_sha256_writes_nothing(self, db_path, tmp_path) -> None:
        assert nodes.db_writer_node(AgentState(file_path="x")) == {}
        assert not (tmp_path / "test.db").exists()

    def test_db_error_does_not_crash(self, monkeypatch) -> None:
        def boom(*a, **k):
            raise sqlite3.OperationalError("disk I/O error")

        monkeypatch.setattr(db, "insert_sample", boom)
        state = AgentState(file_path="x", sample=SampleInfo(sha256=SHA))
        assert nodes.db_writer_node(state) == {}

    def test_node_is_idempotent_across_runs(self, db_path) -> None:
        state = AgentState(file_path="x", sample=SampleInfo(sha256=SHA), source_code=[_fn("0x1", callees=["0x2"])])
        nodes.db_writer_node(state)
        nodes.db_writer_node(state)
        assert len(_rows(db_path, "SELECT * FROM functions")) == 1
        assert len(_rows(db_path, "SELECT * FROM calls")) == 1
        assert len(_rows(db_path, "SELECT * FROM samples")) == 1


class TestGraphWiring:
    @staticmethod
    def _edges():
        return {(e.source, e.target) for e in build_graph().get_graph().edges}

    def test_supervisor_goes_to_db_writer_then_end(self) -> None:
        edges = self._edges()
        assert ("ai_supervisor_agent", "db_writer_node") in edges
        assert ("db_writer_node", "__end__") in edges
        assert ("ai_supervisor_agent", "__end__") not in edges

    def test_fast_track_reaches_db_writer_via_supervisor(self) -> None:
        edges = self._edges()
        assert ("entry_node", "ai_supervisor_agent") in edges  # fast_track
        assert ("ai_supervisor_agent", "db_writer_node") in edges

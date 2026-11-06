"""Tests for db.py, db_writer_node and graph wiring."""

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
        assert cols("findings") == ["id", "sha256", "source", "kind", "value", "address", "confidence",
                                    "finding_id", "verified"]
        assert cols("functions") == [
            "id", "sha256", "offset", "name", "priority", "c_code", "decompile_warnings",
            "llm_summary", "size", "is_library", "capa_hits", "xrefs", "iocs",
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
        assert db.insert_findings(SHA, [f2], db_path) == 1  # reanalysis: old rows are deleted
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
            _fn("0x1", callees=["0x2", "0x3", "0x2"], warnings=["warn é"]),  # duplicate call stored once
            _fn("0x2", name="g"),
        ]
        assert db.insert_functions_and_calls(SHA, fns, db_path) == (2, 2)

        funcs = _rows(db_path, "SELECT offset, name, priority, c_code, decompile_warnings FROM functions ORDER BY id")
        assert funcs[0][:4] == ("0x1", "f", 5, "int f(){}")
        assert json.loads(funcs[0][4]) == ["warn é"]
        assert json.loads(funcs[1][4]) == []
        calls = _rows(db_path, "SELECT sha256, caller_offset, callee_offset FROM calls ORDER BY id")
        assert calls == [(SHA, "0x1", "0x2"), (SHA, "0x1", "0x3")]  # 0x3 is still written even if it is not in the functions table

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


VERDICT = {
    "verdict": "malicious",
    "reasons": ["2 suspicious function(s)"],
    "unknown_reasons": [],
    "coverage": {"total": 3, "analyzed": 3, "skipped": 0, "ratio": 1.0, "min_required": 0.8},
}


class TestVerdictPersistence:
    def test_llm_claims_has_verdict_column(self, db_path) -> None:
        db.init_db(db_path)
        cols = [r[1] for r in _rows(db_path, "PRAGMA table_info(llm_claims)")]
        assert cols == ["id", "sha256", "supervisor_report", "verdict"]

    def test_old_llm_claims_schema_is_migrated_and_keeps_data(self, tmp_path) -> None:
        path = str(tmp_path / "old.db")
        with closing(sqlite3.connect(path)) as conn, conn:
            conn.execute(
                "CREATE TABLE llm_claims (id INTEGER PRIMARY KEY AUTOINCREMENT, sha256 TEXT, supervisor_report TEXT)"
            )
            conn.execute("INSERT INTO llm_claims (sha256, supervisor_report) VALUES ('x', 'old report')")
        db.init_db(path)
        db.init_db(path)  # running again must not raise an ALTER TABLE error
        assert [r[1] for r in _rows(path, "PRAGMA table_info(llm_claims)")][-1] == "verdict"
        assert _rows(path, "SELECT sha256, supervisor_report, verdict FROM llm_claims") == [("x", "old report", None)]

    def test_insert_stores_verdict_as_json(self, db_path) -> None:
        db.init_db(db_path)
        db.insert_llm_claims(SHA, "report", db_path, verdict=VERDICT)
        (stored,) = _rows(db_path, "SELECT verdict FROM llm_claims")[0]
        assert isinstance(stored, str)
        assert json.loads(stored) == VERDICT

    def test_insert_without_verdict_keeps_backward_compat(self, db_path) -> None:
        db.init_db(db_path)
        db.insert_llm_claims(SHA, "report", db_path)
        assert _rows(db_path, "SELECT supervisor_report, verdict FROM llm_claims") == [("report", None)]

    def test_insert_replaces_previous_verdict(self, db_path) -> None:
        db.init_db(db_path)
        db.insert_llm_claims(SHA, "first", db_path, verdict={"verdict": "unknown"})
        db.insert_llm_claims(SHA, "second", db_path, verdict={"verdict": "malicious"})
        rows = _rows(db_path, "SELECT supervisor_report, verdict FROM llm_claims")
        assert [(r, json.loads(v)["verdict"]) for r, v in rows] == [("second", "malicious")]

    def test_get_sample_details_returns_parsed_verdict(self, db_path) -> None:
        db.init_db(db_path)
        db.insert_sample(SampleInfo(sha256=SHA), db_path)
        db.insert_llm_claims(SHA, "report", db_path, verdict=VERDICT)
        assert db.get_sample_details(SHA, db_path)["verdict"] == VERDICT

    def test_get_sample_details_without_claims_has_empty_verdict(self, db_path) -> None:
        db.init_db(db_path)
        db.insert_sample(SampleInfo(sha256=SHA), db_path)
        d = db.get_sample_details(SHA, db_path)
        assert d["verdict"] == {} and d["supervisor_report"] == ""

    def test_get_all_samples_includes_parsed_verdict(self, db_path) -> None:
        db.init_db(db_path)
        db.insert_sample(SampleInfo(sha256=SHA), db_path)
        db.insert_sample(SampleInfo(sha256="b" * 64), db_path)  # sample without a verdict
        db.insert_llm_claims(SHA, "report", db_path, verdict=VERDICT)
        by_sha = {s["sha256"]: s for s in db.get_all_samples(db_path)}
        assert by_sha[SHA]["verdict"] == VERDICT and by_sha[SHA]["has_report"] is True
        assert by_sha["b" * 64]["verdict"] == {} and by_sha["b" * 64]["has_report"] is False
        assert "verdict_json" not in by_sha[SHA]

    @pytest.mark.parametrize("raw", ["not json", "[1, 2]", '"str"', ""])
    def test_corrupt_or_non_dict_verdict_becomes_empty(self, db_path, raw) -> None:
        db.init_db(db_path)
        db.insert_sample(SampleInfo(sha256=SHA), db_path)
        db.insert_llm_claims(SHA, "r", db_path, verdict=raw)
        assert db.get_sample_details(SHA, db_path)["verdict"] == {}
        assert db.get_all_samples(db_path)[0]["verdict"] == {}


class TestFunctionIocs:
    def test_iocs_are_stored_as_json_and_read_back(self, db_path) -> None:
        db.init_db(db_path)
        db.insert_sample(SampleInfo(sha256=SHA), db_path)
        fn = DecompiledFunction(offset="0x1", name="f", c_code="x", iocs=["http://evil.example/é", "10.0.0.1"])
        db.insert_functions_and_calls(SHA, [fn, DecompiledFunction(offset="0x2")], db_path)
        raw = dict(_rows(db_path, "SELECT offset, iocs FROM functions"))
        assert json.loads(raw["0x1"]) == ["http://evil.example/é", "10.0.0.1"]
        assert json.loads(raw["0x2"]) == []
        by_offset = {f["offset"]: f for f in db.get_sample_details(SHA, db_path)["functions"]}
        # the DB stores the raw value; the read path (API/UI) defangs IoCs
        assert by_offset["0x1"]["iocs"] == ["hxxp://evil[.]example/é", "10.0.0[.]1"]
        assert by_offset["0x2"]["iocs"] == []

    def test_old_functions_table_gets_iocs_column_and_old_rows_read_as_empty(self, tmp_path) -> None:
        path = str(tmp_path / "old.db")
        with closing(sqlite3.connect(path)) as conn, conn:
            conn.execute(
                "CREATE TABLE functions (id INTEGER PRIMARY KEY AUTOINCREMENT, sha256 TEXT, offset TEXT, name TEXT, "
                "priority INTEGER, c_code TEXT, decompile_warnings TEXT, llm_summary TEXT, size INTEGER, "
                "is_library BOOLEAN, capa_hits TEXT, xrefs TEXT)"
            )
            conn.execute("INSERT INTO functions (sha256, offset, name) VALUES (?, '0x1', 'f')", (SHA,))
            conn.execute("CREATE TABLE samples (sha256 TEXT PRIMARY KEY, file_type TEXT, route TEXT, packer TEXT, arch TEXT)")
            conn.execute("INSERT INTO samples (sha256) VALUES (?)", (SHA,))
        db.init_db(path)
        assert [r[1] for r in _rows(path, "PRAGMA table_info(functions)")][-1] == "iocs"
        assert db.get_sample_details(SHA, path)["functions"][0]["iocs"] == []

    def test_db_writer_node_persists_function_iocs(self, db_path, monkeypatch) -> None:
        monkeypatch.setattr(db, "DEFAULT_DB_PATH", db_path)
        state = AgentState(
            file_path="x", sample=SampleInfo(sha256=SHA),
            source_code=[DecompiledFunction(offset="0x1", name="f", c_code="x", iocs=["10.0.0.1"])],
        )
        nodes.db_writer_node(state)
        assert db.get_sample_details(SHA, db_path)["functions"][0]["iocs"] == ["10.0.0[.]1"]  # defanged


class TestDbWriterNodeVerdictAndSummaries:
    @pytest.fixture(autouse=True)
    def _isolate_db(self, db_path, monkeypatch):
        monkeypatch.setattr(db, "DEFAULT_DB_PATH", db_path)

    def test_writes_verdict_report_and_function_summaries(self, db_path) -> None:
        state = AgentState(
            file_path="x",
            sample=SampleInfo(sha256=SHA),
            source_code=[
                DecompiledFunction(offset="0x1", name="a", c_code="int a(){}", llm_summary="Performs encryption"),
                DecompiledFunction(offset="0x2", name="b", c_code="int b(){}"),
            ],
            analysis_report="# Report",
            verdict=VERDICT,
        )
        assert nodes.db_writer_node(state) == {}

        assert _rows(db_path, "SELECT offset, llm_summary FROM functions ORDER BY offset") == [
            ("0x1", "Performs encryption"),
            ("0x2", ""),
        ]
        assert json.loads(_rows(db_path, "SELECT verdict FROM llm_claims")[0][0]) == VERDICT
        d = db.get_sample_details(SHA, db_path)
        assert d["verdict"]["verdict"] == "malicious"
        assert {f["offset"]: f["llm_summary"] for f in d["functions"]} == {"0x1": "Performs encryption", "0x2": ""}

    def test_verdict_without_report_is_still_saved(self, db_path) -> None:
        state = AgentState(file_path="x", sample=SampleInfo(sha256=SHA), verdict=VERDICT)
        nodes.db_writer_node(state)
        assert db.get_sample_details(SHA, db_path)["verdict"] == VERDICT

    def test_nothing_written_to_llm_claims_when_no_report_and_no_verdict(self, db_path) -> None:
        nodes.db_writer_node(AgentState(file_path="x", sample=SampleInfo(sha256=SHA)))
        assert _rows(db_path, "SELECT * FROM llm_claims") == []

    def test_reanalysis_overwrites_verdict(self, db_path) -> None:
        base = dict(file_path="x", sample=SampleInfo(sha256=SHA), analysis_report="r")
        nodes.db_writer_node(AgentState(**base, verdict={"verdict": "unknown"}))
        nodes.db_writer_node(AgentState(**base, verdict={"verdict": "malicious"}))
        assert len(_rows(db_path, "SELECT * FROM llm_claims")) == 1
        assert db.get_sample_details(SHA, db_path)["verdict"]["verdict"] == "malicious"


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


class TestFindingIntegrityColumns:
    def test_finding_id_and_verified_roundtrip(self, db_path) -> None:
        db.init_db(db_path)
        db.insert_sample(SampleInfo(sha256=SHA), db_path)
        db.insert_findings(SHA, [
            Finding(source="floss", kind="ip", value="198.51.100.7", finding_id="abcd1234", verified=False),
            Finding(source="yara", kind="rule", value="R", finding_id="ffff0000"),
        ], db_path)
        raw = _rows(db_path, "SELECT finding_id, verified FROM findings ORDER BY id")
        assert raw == [("abcd1234", 0), ("ffff0000", 1)]
        by_source = {f["source"]: f for f in db.get_sample_details(SHA, db_path)["findings"]}
        assert by_source["floss"]["finding_id"] == "abcd1234" and by_source["floss"]["verified"] is False
        assert by_source["yara"]["finding_id"] == "ffff0000" and by_source["yara"]["verified"] is True

    def test_defaults_for_findings_without_the_new_fields(self, db_path) -> None:
        class Legacy:  # legacy type: no finding_id/verified attribute
            source, kind, value, address, confidence = "yara", "rule", "R", "", 1.0

        db.init_db(db_path)
        db.insert_findings(SHA, [Legacy()], db_path)
        assert _rows(db_path, "SELECT finding_id, verified FROM findings") == [("", 1)]

    def test_old_findings_table_is_migrated_and_old_rows_read_as_verified(self, tmp_path) -> None:
        path = str(tmp_path / "old.db")
        with closing(sqlite3.connect(path)) as conn, conn:
            conn.execute(
                "CREATE TABLE findings (id INTEGER PRIMARY KEY AUTOINCREMENT, sha256 TEXT, source TEXT, "
                "kind TEXT, value TEXT, address TEXT, confidence REAL)"
            )
            conn.execute("INSERT INTO findings (sha256, source, kind, value, address, confidence) "
                         "VALUES (?, 'floss', 'ip', '10.0.0.1', '', 1.0)", (SHA,))
            conn.execute("CREATE TABLE samples (sha256 TEXT PRIMARY KEY, file_type TEXT, route TEXT, packer TEXT, arch TEXT)")
            conn.execute("INSERT INTO samples (sha256) VALUES (?)", (SHA,))
        db.init_db(path)
        cols = [r[1] for r in _rows(path, "PRAGMA table_info(findings)")]
        assert cols[-2:] == ["finding_id", "verified"]
        (old,) = db.get_sample_details(SHA, path)["findings"]
        assert old["verified"] is True and old["finding_id"] == ""
        db.init_db(path)  # idempotent

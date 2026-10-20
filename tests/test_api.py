"""main.py FastAPI uç noktaları ve db okuma/yazma yardımcıları için testler."""

from __future__ import annotations

import os
import sqlite3
from contextlib import closing

import pytest
from fastapi.testclient import TestClient

import db
import main
import nodes
from nodes import compute_sha256
from state import AgentState, DecompiledFunction, Finding, SampleInfo

SHA = "b" * 64


@pytest.fixture
def db_path(tmp_path, monkeypatch):
    path = str(tmp_path / "api.db")
    monkeypatch.setattr(db, "DEFAULT_DB_PATH", path)
    return path


@pytest.fixture
def client(db_path):
    main._JOBS.clear()
    return TestClient(main.app)


class FakeGraph:
    """Gerçek db_writer_node ile sonucu veritabanına yazan sahte graph."""

    def __init__(self):
        self.seen_paths: list[str] = []

    def invoke(self, state: AgentState):
        self.seen_paths.append(state.file_path)
        assert os.path.isfile(state.file_path)  # analiz sırasında dosya var
        sha = compute_sha256(state.file_path)
        nodes.db_writer_node(
            AgentState(
                file_path=state.file_path,
                sample=SampleInfo(sha256=sha, file_type="PE", route="native", packer="none", arch="x86-64"),
                findings=[Finding(source="capa", kind="rule", value="encrypt data", address="0x401000")],
                source_code=[
                    DecompiledFunction(
                        offset="0x401000", name="FUN_401000", priority=9, c_code="int f(){}", size=12,
                        callees=["0x402000"], capa_hits=["encrypt data"], xrefs=["0x500000"],
                        decompile_warnings=["w"], llm_summary="şifreler", is_library=False,
                    )
                ],
                analysis_report="# Rapor\nkanıt var",
            )
        )
        return {}


def _upload(client, name="a.exe", data=b"MZ-sample"):
    return client.post("/api/upload", files={"file": (name, data, "application/octet-stream")})


# --------------------------------------------------------------------------- #
# db: yeni sütunlar, llm_claims, migrasyon, okuma yardımcıları
# --------------------------------------------------------------------------- #
class TestDbExtensions:
    def test_functions_new_columns_and_llm_claims_table(self, db_path) -> None:
        db.init_db(db_path)
        with closing(sqlite3.connect(db_path)) as conn:
            cols = [r[1] for r in conn.execute("PRAGMA table_info(functions)")]
            assert cols[-5:] == ["llm_summary", "size", "is_library", "capa_hits", "xrefs"]
            assert [r[1] for r in conn.execute("PRAGMA table_info(llm_claims)")] == ["id", "sha256", "supervisor_report"]

    def test_old_schema_is_migrated(self, tmp_path) -> None:
        path = str(tmp_path / "old.db")
        with closing(sqlite3.connect(path)) as conn, conn:
            conn.execute(
                "CREATE TABLE functions (id INTEGER PRIMARY KEY AUTOINCREMENT, sha256 TEXT, offset TEXT, "
                "name TEXT, priority INTEGER, c_code TEXT, decompile_warnings TEXT)"
            )
            conn.execute("INSERT INTO functions (sha256, offset) VALUES ('x', '0x1')")
        db.init_db(path)
        with closing(sqlite3.connect(path)) as conn:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(functions)")}
            assert {"llm_summary", "size", "is_library", "capa_hits", "xrefs"} <= cols
            assert conn.execute("SELECT COUNT(*) FROM functions").fetchone()[0] == 1  # veri korunur

    def test_insert_functions_serializes_new_columns_as_json(self, db_path) -> None:
        db.init_db(db_path)
        fn = DecompiledFunction(
            offset="0x1", capa_hits=["r ü"], xrefs=["0x9"], llm_summary="s", size=7, is_library=True
        )
        db.insert_functions_and_calls(SHA, [fn], db_path)
        with closing(sqlite3.connect(db_path)) as conn:
            row = conn.execute("SELECT llm_summary, size, is_library, capa_hits, xrefs FROM functions").fetchone()
        assert row == ("s", 7, 1, '["r ü"]', '["0x9"]')

    def test_insert_llm_claims_replaces_previous(self, db_path) -> None:
        db.init_db(db_path)
        db.insert_llm_claims(SHA, "ilk", db_path)
        db.insert_llm_claims(SHA, "ikinci", db_path)
        with closing(sqlite3.connect(db_path)) as conn:
            assert conn.execute("SELECT supervisor_report FROM llm_claims").fetchall() == [("ikinci",)]

    def test_get_all_samples_empty_db_works(self, db_path) -> None:
        assert db.get_all_samples(db_path) == []

    def test_get_sample_details_unknown(self, db_path) -> None:
        assert db.get_sample_details("yok", db_path) is None

    def test_get_sample_details_roundtrip(self, db_path) -> None:
        db.init_db(db_path)
        db.insert_sample(SampleInfo(sha256=SHA, file_type="PE"), db_path)
        db.insert_functions_and_calls(
            SHA,
            [DecompiledFunction(offset="0x1", priority=1, callees=["0x2"]), DecompiledFunction(offset="0x2", priority=9)],
            db_path,
        )
        db.insert_llm_claims(SHA, "rapor", db_path)
        d = db.get_sample_details(SHA, db_path)
        assert [f["offset"] for f in d["functions"]] == ["0x2", "0x1"]  # öncelik azalan
        assert d["functions"][1]["callees"] == ["0x2"]
        assert d["supervisor_report"] == "rapor"
        assert db.get_all_samples(db_path)[0]["has_report"] is True


class TestDbWriterNodeReport:
    def test_writes_supervisor_report(self, db_path, monkeypatch) -> None:
        state = AgentState(file_path="x", sample=SampleInfo(sha256=SHA), analysis_report="# R")
        nodes.db_writer_node(state)
        assert db.get_sample_details(SHA, db_path)["supervisor_report"] == "# R"

    def test_empty_report_writes_nothing(self, db_path) -> None:
        nodes.db_writer_node(AgentState(file_path="x", sample=SampleInfo(sha256=SHA)))
        assert db.get_sample_details(SHA, db_path)["supervisor_report"] == ""


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #
class TestIndex:
    def test_serves_self_contained_html(self, client) -> None:
        res = client.get("/")
        assert res.status_code == 200
        assert "text/html" in res.headers["content-type"]
        assert "CrowbarAF" in res.text and "/api/upload" in res.text and "/api/samples" in res.text
        assert "http://" not in res.text and "https://" not in res.text  # CDN yok: çevrimdışı çalışır
        assert "innerHTML" not in res.text  # dinamik veri HTML olarak enjekte edilmez


class TestUploadAndRead:
    def test_empty_list(self, client) -> None:
        assert client.get("/api/samples").json() == []

    def test_upload_runs_graph_and_results_are_readable(self, client, monkeypatch) -> None:
        graph = FakeGraph()
        monkeypatch.setattr(main, "_get_graph", lambda: graph)

        res = _upload(client, "evil.exe", b"MZ-bytes")
        assert res.status_code == 202
        body = res.json()
        assert body["status"] == "running" and body["filename"] == "evil.exe"
        sha = body["sha256"]
        assert len(sha) == 64

        # analiz bitti: geçici klasör silindi, iş kaydı düştü
        assert not os.path.exists(os.path.dirname(graph.seen_paths[0]))
        assert main._JOBS == {}

        samples = client.get("/api/samples").json()
        assert [(s["sha256"], s["findings_count"], s["functions_count"], s["has_report"]) for s in samples] == [
            (sha, 1, 1, True)
        ]

        d = client.get(f"/api/samples/{sha}").json()
        assert d["analysis_status"] == "done"
        assert d["sample"]["route"] == "native"
        assert d["findings"][0]["value"] == "encrypt data" and d["findings"][0]["address"] == "0x401000"
        fn = d["functions"][0]
        assert (fn["name"], fn["llm_summary"], fn["size"], fn["capa_hits"], fn["xrefs"], fn["callees"]) == (
            "FUN_401000", "şifreler", 12, ["encrypt data"], ["0x500000"], ["0x402000"],
        )
        assert fn["decompile_warnings"] == ["w"] and fn["is_library"] is False
        assert d["supervisor_report"].startswith("# Rapor")

    def test_filename_is_sanitized(self, client, monkeypatch) -> None:
        graph = FakeGraph()
        monkeypatch.setattr(main, "_get_graph", lambda: graph)
        _upload(client, "..\\..\\etc/evil.exe")
        assert os.path.basename(graph.seen_paths[0]) == "evil.exe"
        assert graph.seen_paths[0].startswith(os.path.realpath(os.path.dirname(graph.seen_paths[0]))[:3])

    @pytest.mark.parametrize("raw, expected", [("a/b/c.exe", "c.exe"), ("..", "sample.bin"), ("", "sample.bin"), (None, "sample.bin"), ("x<y>.exe", "x_y_.exe")])
    def test_safe_filename(self, raw, expected) -> None:
        assert main._safe_filename(raw) == expected

    def test_empty_file_rejected(self, client, monkeypatch) -> None:
        monkeypatch.setattr(main, "_get_graph", lambda: pytest.fail("graph çalışmamalı"))
        res = _upload(client, data=b"")
        assert res.status_code == 400

    def test_too_large_rejected_and_cleaned(self, client, monkeypatch) -> None:
        monkeypatch.setattr(main, "MAX_UPLOAD_BYTES", 10)
        monkeypatch.setattr(main, "_get_graph", lambda: pytest.fail("graph çalışmamalı"))
        created = []
        real_mkdtemp = main.tempfile.mkdtemp
        monkeypatch.setattr(main.tempfile, "mkdtemp", lambda **k: created.append(real_mkdtemp(**k)) or created[-1])
        res = _upload(client, data=b"x" * 100)
        assert res.status_code == 413
        assert created and not os.path.exists(created[0])

    def test_graph_failure_is_reported_and_cleaned(self, client, monkeypatch) -> None:
        paths = []

        class Boom:
            def invoke(self, state):
                paths.append(state.file_path)
                raise RuntimeError("ghidra patladı")

        monkeypatch.setattr(main, "_get_graph", lambda: Boom())
        sha = _upload(client, data=b"MZ-boom").json()["sha256"]

        assert not os.path.exists(os.path.dirname(paths[0]))
        res = client.get(f"/api/samples/{sha}")
        assert res.status_code == 500
        assert res.json()["analysis_status"] == "error" and "ghidra patladı" in res.json()["error"]

    def test_unknown_sample_404(self, client) -> None:
        assert client.get("/api/samples/" + "0" * 64).status_code == 404

    def test_running_job_returns_202(self, client) -> None:
        main._JOBS[SHA] = {"status": "running", "error": ""}
        res = client.get(f"/api/samples/{SHA}")
        assert res.status_code == 202 and res.json()["analysis_status"] == "running"

    def test_duplicate_upload_while_running_does_not_start_second_job(self, client, monkeypatch) -> None:
        monkeypatch.setattr(main, "_get_graph", lambda: pytest.fail("ikinci iş başlamamalı"))
        sha = compute_sha256_of_bytes(b"MZ-dup")
        main._JOBS[sha] = {"status": "running", "error": ""}
        res = _upload(client, data=b"MZ-dup")
        assert res.status_code == 202 and res.json()["sha256"] == sha

    def test_reanalysis_shows_running_status_with_old_data(self, client, db_path) -> None:
        db.init_db(db_path)
        db.insert_sample(SampleInfo(sha256=SHA), db_path)
        main._JOBS[SHA] = {"status": "running", "error": ""}
        d = client.get(f"/api/samples/{SHA}").json()
        assert d["analysis_status"] == "running" and d["sample"]["sha256"] == SHA


def compute_sha256_of_bytes(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


class TestCliPreserved:
    def test_cli_entry_points_still_exist(self) -> None:
        assert callable(main.main)
        assert main.app.title == "CrowbarAF"

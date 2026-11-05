"""Tests for the v2 split UI API and GuestControl transport."""
from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

import main
import web_v2
from state import AgentState
from vm_transport import GuestControlConfig, GuestControlTransport


def _state_json(tmp_path: Path) -> Path:
    state = AgentState(file_path="sample.bin")
    path = tmp_path / "state.json"
    path.write_text(state.model_dump_json(indent=2), encoding="utf-8")
    path.chmod(0o600)
    return path


def _client() -> TestClient:
    return TestClient(main.app)


def test_v2_ui_served_and_has_four_tabs():
    res = _client().get("/v2")
    assert res.status_code == 200
    assert "1 · Offline (VM)" in res.text
    assert "2 · Host / LLM" in res.text
    assert "3 · History / Compare" in res.text
    assert "4 · Setup" in res.text
    assert "innerHTML" not in res.text


def test_host_rejects_invalid_state(tmp_path):
    client = _client()
    bad = tmp_path / "bad.json"
    bad.write_text('{"not": "a state"}', encoding="utf-8")
    res = client.post("/api/v2/host", files={"file": ("bad.json", bad.read_bytes(), "application/json")})
    assert res.status_code == 400


def test_offline_job_flow_with_fake_transport(tmp_path, monkeypatch):
    monkeypatch.setattr(web_v2, "UPLOAD_DIR", tmp_path / "samples")
    monkeypatch.setattr(web_v2, "STATE_DIR", tmp_path / "states")
    web_v2.UPLOAD_DIR.mkdir()
    web_v2.STATE_DIR.mkdir()
    state_template = AgentState(file_path="sample.bin").model_dump_json(indent=2)

    def fake_run_offline(self, sample_path, out_path, **kwargs):
        Path(out_path).write_text(state_template, encoding="utf-8")
        Path(out_path).chmod(0o600)
        return out_path

    monkeypatch.setattr(GuestControlTransport, "run_offline", fake_run_offline)
    client = _client()
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ harmless test")
    res = client.post(
        "/api/v2/offline",
        files={"file": ("sample.bin", sample.read_bytes(), "application/octet-stream")},
        data={"vm_name": "vm", "vm_user": "kali", "vm_password": "secret",
              "repo_dir": "/repo", "profile": "deep", "max_decompile": "10"},
    )
    assert res.status_code == 200, res.text
    job_id = res.json()["job_id"]
    job = client.get(f"/api/v2/jobs/{job_id}").json()
    assert job["status"] == "done", job
    assert job["result"]["state_file"].endswith(".json")
    state_res = client.get(f"/api/v2/jobs/{job_id}/state")
    assert state_res.status_code == 200
    assert "secret" not in state_res.text


def test_transport_uses_password_file_and_expected_args(tmp_path, monkeypatch):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"test")
    out = tmp_path / "state.json"
    transport = GuestControlTransport(GuestControlConfig(
        vm_name="vm", username="kali", password="secret", repo_dir="/repo"))
    calls = []
    monkeypatch.setattr(transport, "mkdir", lambda p: calls.append(("mkdir", p)))
    monkeypatch.setattr(transport, "copyto", lambda local, guest: calls.append(("copyto", local, guest)))
    monkeypatch.setattr(transport, "run", lambda exe, args, timeout=None: calls.append(("run", exe, args)) or "ok")
    monkeypatch.setattr(transport, "copyfrom", lambda guest, local: (Path(local).write_text("{}"), calls.append(("copyfrom", guest, local))))
    monkeypatch.setattr(transport, "cleanup", lambda p: calls.append(("cleanup", p)))
    transport.run_offline(str(sample), str(out), profile="core", max_decompile=5)
    assert calls[0][0] == "mkdir"
    assert calls[1] == ("copyto", str(sample), "/repo/incoming/" + calls[1][2].split("/")[-1])
    assert calls[2][0] == "run"
    assert "--profile" in calls[2][2]
    assert calls[2][2][calls[2][2].index("--profile") + 1] == "core"
    assert calls[-1][0] == "cleanup"


def test_transport_does_not_put_password_in_process_args(monkeypatch):
    transport = GuestControlTransport(GuestControlConfig(
        vm_name="vm", username="kali", password="super-secret", repo_dir="/repo"))
    seen = {}

    def fake_vbox(args, timeout=None):
        seen["args"] = list(args)
        return "ok"

    monkeypatch.setattr(transport, "_vbox", fake_vbox)
    transport.run("/bin/echo", ["hello"])
    assert "--passwordfile=" in " ".join(seen["args"])
    assert "super-secret" not in " ".join(seen["args"])


def test_opencode_provider_preset(monkeypatch):
    monkeypatch.delenv("CROWBAR_LLM_API_KEY", raising=False)
    client = web_v2._build_client({"provider": "opencode", "model": "", "base_url": ""})
    assert client.provider == "openai"
    assert client.model == "deepseek-v4.1-flash"
    assert client.base_url == "https://opencode.ai/inference/go/openai"


def test_offline_vm_path_without_host_file(tmp_path, monkeypatch):
    monkeypatch.setattr(web_v2, "UPLOAD_DIR", tmp_path / "samples")
    monkeypatch.setattr(web_v2, "STATE_DIR", tmp_path / "states")
    web_v2.UPLOAD_DIR.mkdir()
    web_v2.STATE_DIR.mkdir()
    state_template = AgentState(file_path="sample.bin").model_dump_json(indent=2)
    seen = {}

    def fake_run_offline(self, sample_path, out_path, **kwargs):
        seen["sample_path"] = sample_path
        seen["remote_sample"] = kwargs.get("remote_sample")
        Path(out_path).write_text(state_template, encoding="utf-8")
        Path(out_path).chmod(0o600)
        return out_path

    monkeypatch.setattr(GuestControlTransport, "run_offline", fake_run_offline)
    client = _client()
    res = client.post(
        "/api/v2/offline",
        data={"source_mode": "vm", "vm_path": "/samples/real.bin",
              "vm_name": "vm", "vm_user": "kali", "vm_password": "secret",
              "repo_dir": "/repo", "profile": "deep", "max_decompile": "10"},
    )
    assert res.status_code == 200, res.text
    job = client.get(f"/api/v2/jobs/{res.json()['job_id']}").json()
    assert job["status"] == "done"
    assert job["result"]["source"] == "vm_path"
    assert seen["sample_path"] is None
    assert seen["remote_sample"] == "/samples/real.bin"


def test_offline_vm_path_rejects_relative_path():
    client = _client()
    res = client.post(
        "/api/v2/offline",
        data={"source_mode": "vm", "vm_path": "relative.bin",
              "vm_name": "vm", "vm_user": "kali", "vm_password": "secret"},
    )
    assert res.status_code == 400

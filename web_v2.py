"""v2 host UI API: offline VM run, host LLM import, and history.

Routes are intentionally separate from the legacy ``/api/upload`` pipeline so
the existing UI/tests keep working while the split-mode UI is added.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse

import db
import host_analyze
from llm_layer.client import LLMClient
from sandbox.validate_state import validate_state
from state import AgentState
from vm_transport import GuestControlConfig, GuestControlTransport

logger = logging.getLogger(__name__)

router = APIRouter()
MAX_UPLOAD_BYTES = int(os.getenv("CROWBAR_MAX_UPLOAD_MB", "200")) * 1024 * 1024
MAX_STATE_MB = int(os.getenv("CROWBAR_HOST_MAX_STATE_MB", "500"))
DATA_DIR = Path(os.getenv("CROWBAR_UI_DATA_DIR", "runs/ui")).expanduser().resolve()
UPLOAD_DIR = DATA_DIR / "samples"
STATE_DIR = DATA_DIR / "states"
for directory in (DATA_DIR, UPLOAD_DIR, STATE_DIR):
    directory.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass

_JOBS: dict[str, dict[str, Any]] = {}
_JOBS_LOCK = threading.Lock()
_LLM_ENV_LOCK = threading.Lock()

DEFAULT_VM_NAME = os.getenv("CROWBAR_VM_NAME", "kali-linux-2026.2-virtualbox-amd64")
DEFAULT_VM_USER = os.getenv("CROWBAR_VM_USER", "kali")
DEFAULT_VM_REPO = os.getenv("CROWBAR_VM_REPO", "/home/kali/Desktop/CrowbarAF")


def _job_new(kind: str) -> str:
    job_id = uuid.uuid4().hex
    with _JOBS_LOCK:
        _JOBS[job_id] = {
            "id": job_id, "kind": kind, "status": "queued", "stage": "queued",
            "created": time.time(), "error": "", "result": {},
        }
    return job_id


def _job_update(job_id: str, **fields: Any) -> None:
    with _JOBS_LOCK:
        if job_id in _JOBS:
            _JOBS[job_id].update(fields)


def _job_get(job_id: str) -> dict[str, Any]:
    with _JOBS_LOCK:
        if job_id not in _JOBS:
            raise HTTPException(status_code=404, detail="job not found")
        # Never expose credentials; jobs do not store them in the first place.
        return dict(_JOBS[job_id])


def _safe_filename(name: str | None) -> str:
    base = os.path.basename((name or "").replace("\\", "/"))
    base = re.sub(r"[\x00-\x1f<>:\"|?*]", "_", base).strip(" .")
    return base or "sample.bin"


def _save_upload(upload: UploadFile, dest: Path) -> int:
    size = 0
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "wb") as out:
        while chunk := upload.file.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_UPLOAD_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail=f"file exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MB",
                )
            out.write(chunk)
    try:
        os.chmod(dest, 0o600)
    except OSError:
        pass
    return size


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _validate_state_file(path: Path) -> None:
    result = validate_state(path, max_mb=MAX_STATE_MB, allow_empty_summaries=True)
    if not result.ok:
        raise ValueError("state validation failed: " + "; ".join(result.errors[:8]))


def _run_offline_job(
    job_id: str,
    sample: Path,
    state_path: Path,
    config: GuestControlConfig,
    options: dict[str, Any],
) -> None:
    try:
        _job_update(job_id, status="running", stage="copying to VM")
        transport = GuestControlTransport(config)
        _job_update(job_id, stage="VM analysis")
        transport.run_offline(str(sample), str(state_path), **options)
        _job_update(job_id, stage="validating state")
        _validate_state_file(state_path)
        sha = _sha256(sample)
        _job_update(
            job_id, status="done", stage="done",
            result={
                "sha256": sha,
                "state_file": state_path.name,
                "state_bytes": state_path.stat().st_size,
                "state_sha256": _sha256(state_path),
            },
        )
    except Exception as exc:  # noqa: BLE001 - report to caller
        logger.exception("[web_v2] offline job failed: %s", job_id)
        _job_update(job_id, status="error", stage="error",
                    error=f"{type(exc).__name__}: {exc}"[:1000])
    finally:
        # Keep the state for download; remove the host-side sample copy.
        try:
            sample.unlink(missing_ok=True)
        except OSError:
            pass


def _build_client(fields: dict[str, Any]) -> LLMClient:
    provider = (fields.get("provider") or os.getenv("CROWBAR_LLM_PROVIDER", "ollama")).strip()
    model = (fields.get("model") or os.getenv("CROWBAR_LLM_MODEL")
             or os.getenv("CROWBAR_OLLAMA_MODEL", "llama3.1")).strip()
    base_url = (fields.get("base_url") or os.getenv("CROWBAR_LLM_BASE_URL")
                or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")).strip()
    return LLMClient(
        provider=provider,
        model=model,
        base_url=base_url,
        api_key=os.getenv("CROWBAR_LLM_API_KEY"),
        num_ctx=int(fields.get("num_ctx") or os.getenv("CROWBAR_LLM_NUM_CTX", "32768")),
        num_predict=int(fields.get("num_predict") or os.getenv("CROWBAR_LLM_NUM_PREDICT", "1200")),
        user_agent=os.getenv("CROWBAR_LLM_USER_AGENT", "crowbaraf/0.1"),
        session_id=os.getenv("CROWBAR_LLM_SESSION_ID") or None,
    )


def _run_host_job(
    job_id: str,
    state_path: Path,
    llm_fields: dict[str, Any],
    budget_tokens: int,
    report: bool,
) -> None:
    try:
        _job_update(job_id, status="running", stage="validating state")
        _validate_state_file(state_path)
        state = host_analyze.load_state(state_path)
        _job_update(job_id, stage="LLM")
        client = _build_client(llm_fields)
        with _LLM_ENV_LOCK:
            old_workers = os.environ.get("CROWBAR_LLM_MAX_WORKERS")
            old_min = os.environ.get("CROWBAR_LLM_MIN_PRIORITY")
            if llm_fields.get("max_workers"):
                os.environ["CROWBAR_LLM_MAX_WORKERS"] = str(int(llm_fields["max_workers"]))
            if llm_fields.get("min_priority") is not None:
                os.environ["CROWBAR_LLM_MIN_PRIORITY"] = str(int(llm_fields["min_priority"]))
            try:
                merged = host_analyze.analyze_state(
                    state, client=client, budget_tokens=budget_tokens, report=report)
            finally:
                if old_workers is None:
                    os.environ.pop("CROWBAR_LLM_MAX_WORKERS", None)
                else:
                    os.environ["CROWBAR_LLM_MAX_WORKERS"] = old_workers
                if old_min is None:
                    os.environ.pop("CROWBAR_LLM_MIN_PRIORITY", None)
                else:
                    os.environ["CROWBAR_LLM_MIN_PRIORITY"] = old_min

        out_path = STATE_DIR / f"{job_id}.llm.json"
        host_analyze.write_state(merged, out_path)
        _job_update(job_id, stage="saving database")
        try:
            saved = host_analyze.persist_state(merged)
        except Exception as exc:  # noqa: BLE001 - state is still available
            logger.warning("[web_v2] DB save failed: %s", exc)
            saved = {"error": str(exc)[:300]}
        _job_update(
            job_id, status="done", stage="done",
            result={
                "sha256": merged.sample.sha256,
                "verdict": merged.verdict.get("verdict", "unknown") if merged.verdict else "unknown",
                "state_file": out_path.name,
                "state_bytes": out_path.stat().st_size,
                "state_sha256": _sha256(out_path),
                "db": saved,
            },
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("[web_v2] host job failed: %s", job_id)
        _job_update(job_id, status="error", stage="error",
                    error=f"{type(exc).__name__}: {exc}"[:1000])


@router.post("/api/v2/offline")
def offline_analyze(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    vm_name: str = Form(DEFAULT_VM_NAME),
    vm_user: str = Form(DEFAULT_VM_USER),
    vm_password: str = Form(...),
    repo_dir: str = Form(DEFAULT_VM_REPO),
    profile: str = Form("deep"),
    max_decompile: int = Form(100),
    ghidra_timeout: int = Form(1200),
    capa_timeout: int = Form(300),
    floss_timeout: int = Form(300),
) -> dict[str, Any]:
    if profile not in ("core", "deep"):
        raise HTTPException(status_code=400, detail="profile must be core or deep")
    if not vm_name.strip() or not vm_user.strip() or not vm_password:
        raise HTTPException(status_code=400, detail="VM name/user/password required")
    job_id = _job_new("offline")
    job_dir = UPLOAD_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    sample_path = job_dir / _safe_filename(file.filename)
    size = _save_upload(file, sample_path)
    if size == 0:
        shutil.rmtree(job_dir, ignore_errors=True)
        raise HTTPException(status_code=400, detail="empty file")
    state_path = STATE_DIR / f"{job_id}.json"
    config = GuestControlConfig(
        vm_name=vm_name.strip(), username=vm_user.strip(), password=vm_password,
        repo_dir=repo_dir.strip() or DEFAULT_VM_REPO,
    )
    options = dict(
        profile=profile,
        max_decompile=max(1, min(int(max_decompile), 1000)),
        ghidra_timeout=max(30, int(ghidra_timeout)),
        capa_timeout=max(30, int(capa_timeout)),
        floss_timeout=max(30, int(floss_timeout)),
    )
    background_tasks.add_task(_run_offline_job, job_id, sample_path, state_path, config, options)
    return {"job_id": job_id, "status": "queued"}


@router.post("/api/v2/host")
def host_analyze_upload(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    provider: str = Form("ollama"),
    model: str = Form(""),
    base_url: str = Form(""),
    num_ctx: int = Form(32768),
    num_predict: int = Form(1200),
    budget_tokens: int = Form(6000),
    max_workers: int = Form(1),
    min_priority: int = Form(0),
    no_report: str = Form(""),
) -> dict[str, Any]:
    job_id = _job_new("host")
    job_dir = UPLOAD_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    state_path = job_dir / "state.json"
    size = _save_upload(file, state_path)
    if size == 0:
        shutil.rmtree(job_dir, ignore_errors=True)
        raise HTTPException(status_code=400, detail="empty state")
    try:
        _validate_state_file(state_path)
    except Exception as exc:  # noqa: BLE001
        shutil.rmtree(job_dir, ignore_errors=True)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    fields = dict(
        provider=provider, model=model, base_url=base_url,
        num_ctx=num_ctx, num_predict=num_predict,
        max_workers=max(1, min(int(max_workers), 32)),
        min_priority=max(0, int(min_priority)),
    )
    background_tasks.add_task(
        _run_host_job, job_id, state_path, fields,
        max(128, min(int(budget_tokens), 100000)),
        not bool(no_report),
    )
    return {"job_id": job_id, "status": "queued"}


@router.get("/api/v2/jobs/{job_id}")
def job_status(job_id: str) -> dict[str, Any]:
    return _job_get(job_id)


@router.get("/api/v2/jobs/{job_id}/state")
def job_state(job_id: str) -> FileResponse:
    job = _job_get(job_id)
    if job.get("status") != "done":
        raise HTTPException(status_code=409, detail="job is not done")
    name = (job.get("result") or {}).get("state_file") or ""
    # The filename is generated by the server; never accept a client path.
    if not re.fullmatch(r"[a-f0-9]{32}(\.llm)?\.json", name):
        raise HTTPException(status_code=404, detail="state not found")
    path = STATE_DIR / name
    if not path.is_file():
        raise HTTPException(status_code=404, detail="state not found")
    return FileResponse(path, media_type="application/json", filename=name)


@router.get("/api/v2/setup/status")
def setup_status() -> dict[str, Any]:
    """Host-side environment check; the offline VM check is done from the UI."""
    script = Path(__file__).resolve().parent / "scripts" / "check_tools.py"
    try:
        proc = subprocess.run(
            [sys.executable, str(script)],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=30, check=False,
        )
        return {
            "ok": proc.returncode == 0,
            "output": ((proc.stdout or "") + (proc.stderr or ""))[-12000:],
        }
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "output": f"{type(exc).__name__}: {exc}"}


@router.get("/api/v2/history")
def history() -> list[dict[str, Any]]:
    return db.get_all_samples()

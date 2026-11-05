"""VirtualBox GuestControl transport for the offline VM.

The host UI uses this module to copy a sample into the offline VM, run the
deterministic pipeline (``main.py --no-llm --no-db``) and copy the resulting
``state.json`` back. No network, shared folder, clipboard or USB is used.

Security notes:
- ``VBoxManage`` is invoked with an argument list (never ``shell=True``).
- The guest password is held only in memory for the duration of a job; it is
  never logged or written to the state.
- Only the expected sample and state paths are copied.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

VBOXMANAGE = os.getenv("CROWBAR_VBOXMANAGE", "VBoxManage")


class GuestControlError(RuntimeError):
    """VBoxManage guestcontrol failed."""


@dataclass
class GuestControlConfig:
    vm_name: str
    username: str
    password: str = field(repr=False)
    repo_dir: str = "/home/kali/Desktop/CrowbarAF"
    python: str = ""          # default: <repo_dir>/.venv/bin/python
    env: dict[str, str] = field(default_factory=dict)  # guest --putenv
    timeout: int = 1800


class GuestControlTransport:
    def __init__(self, config: GuestControlConfig):
        self.config = config
        self.python = config.python or f"{config.repo_dir}/.venv/bin/python"

    def _vbox(self, args: list[str], timeout: int | None = None) -> str:
        cmd = [VBOXMANAGE, "guestcontrol", self.config.vm_name, *args]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout or self.config.timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            raise GuestControlError(f"{VBOXMANAGE} not found: {exc}") from exc
        except subprocess.TimeoutExpired as exc:
            raise GuestControlError(
                f"guestcontrol timeout after {timeout or self.config.timeout}s: {args[0]}"
            ) from exc
        if proc.returncode != 0:
            # Never echo the password; VBoxManage's own stderr may be noisy.
            detail = (proc.stderr or proc.stdout or "").strip()[:800]
            raise GuestControlError(
                f"guestcontrol {args[0]} failed (exit {proc.returncode}): {detail}"
            )
        return (proc.stdout or "").strip()

    @contextmanager
    def _auth(self):
        """Use a 0600 password file so the secret is not in process arguments."""
        fd, path = tempfile.mkstemp(prefix="crowbar-vbox-pass-", dir="/tmp")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(self.config.password)
            yield ["--username", self.config.username, f"--passwordfile={path}"]
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    def run(self, exe: str, args: list[str], timeout: int | None = None) -> str:
        with self._auth() as auth:
            env_args = [f"--putenv={k}={v}" for k, v in self.config.env.items() if v]
            return self._vbox(
                ["run", "--exe", exe, "--cwd", self.config.repo_dir,
                 *env_args, *auth, "--wait-stdout", "--wait-stderr", "--", *args],
                timeout=timeout,
            )

    def copyto(self, local: str, guest_dir: str) -> None:
        with self._auth() as auth:
            self._vbox([
                "copyto", *auth, f"--target-directory={guest_dir.rstrip('/')}/", local,
            ])

    def copyfrom(self, guest: str, local: str) -> None:
        with self._auth() as auth:
            self._vbox(["copyfrom", *auth, guest, local])

    def mkdir(self, guest_dir: str) -> None:
        with self._auth() as auth:
            self._vbox(["mkdir", *auth, "--parents", guest_dir])

    def cleanup(self, guest_dir: str) -> None:
        try:
            self.run("/bin/rm", ["-rf", guest_dir], timeout=60)
        except GuestControlError as exc:
            logger.warning("[vm_transport] remote cleanup failed: %s", exc)

    def run_offline(
        self,
        sample_path: str | None,
        out_path: str,
        *,
        remote_sample: str | None = None,
        profile: str = "deep",
        max_decompile: int = 100,
        ghidra_timeout: int = 1200,
        capa_timeout: int = 300,
        floss_timeout: int = 300,
    ) -> str:
        """Copy sample to VM, run deterministic pipeline, copy state back.

        Returns the local state path. The guest runs without LLM/DB and gets a
        fresh per-job directory; only the result state is copied out.
        """
        local_sample = Path(sample_path).expanduser().resolve() if sample_path else None
        local_out = Path(out_path).expanduser().resolve()
        if remote_sample is None:
            if local_sample is None or not local_sample.is_file():
                raise ValueError(f"sample not found: {local_sample}")
        else:
            remote_sample = str(remote_sample).strip()
            if not remote_sample.startswith("/") or "\n" in remote_sample or "\x00" in remote_sample:
                raise ValueError("VM sample path must be an absolute Linux path")
        local_out.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(local_out.parent, 0o700)
        except OSError:
            pass

        job_id = uuid.uuid4().hex
        remote_dir = f"{self.config.repo_dir}/incoming/{job_id}"
        remote_sample = f"{remote_dir}/{local_sample.name}"
        remote_state = f"{remote_dir}/state.json"
        self.mkdir(remote_dir)
        self.copyto(str(local_sample), remote_dir)
        try:
            self.run(
                self.python,
                [
                    f"{self.config.repo_dir}/main.py", remote_sample,
                    "--no-llm", "--no-db",
                    "--out", remote_state,
                    "--profile", profile,
                    "--max-decompile", str(int(max_decompile)),
                    "--ghidra-timeout", str(int(ghidra_timeout)),
                    "--capa-timeout", str(int(capa_timeout)),
                    "--floss-timeout", str(int(floss_timeout)),
                ],
                timeout=max(int(ghidra_timeout) + int(capa_timeout) + int(floss_timeout) + 120,
                            self.config.timeout),
            )
            self.copyfrom(remote_state, str(local_out))
            try:
                os.chmod(local_out, 0o600)
            except OSError:
                pass
        finally:
            self.cleanup(remote_dir)
        return str(local_out)


def state_sha256(path: str) -> str:
    """SHA-256 of a host-side state file (for display/job correlation)."""
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def ensure_vboxmanage() -> bool:
    return shutil.which(VBOXMANAGE) is not None

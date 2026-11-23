"""Shared helpers for sanitizing upload names and storing uploads on disk."""

from __future__ import annotations

import os
import re
from pathlib import Path

from fastapi import HTTPException, UploadFile


def safe_filename(name: str | None) -> str:
    """Sanitizes path components and control characters (against path traversal)."""
    base = os.path.basename((name or "").replace("\\", "/"))
    base = re.sub(r"[\x00-\x1f<>:\"|?*]", "_", base).strip(" .")
    return base or "sample.bin"


def save_upload(
    upload: UploadFile,
    dest: str | os.PathLike[str],
    max_bytes: int,
    chunk_size: int = 1024 * 1024,
) -> int:
    """Writes the uploaded file to disk in chunks and returns the byte count.

    Missing parent directories are created and the saved file is made private
    (``0o600``). A partially written file is removed when ``max_bytes`` is exceeded.
    """
    path = Path(dest)
    path.parent.mkdir(parents=True, exist_ok=True)
    size = 0
    exceeded = False
    with open(path, "wb") as out:
        while chunk := upload.file.read(chunk_size):
            size += len(chunk)
            if size > max_bytes:
                exceeded = True
                break
            out.write(chunk)
    if exceeded:
        try:
            path.unlink()
        except OSError:
            pass
        raise HTTPException(
            status_code=413,
            detail=f"file exceeds {max_bytes // (1024 * 1024)} MB limit",
        )
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return size

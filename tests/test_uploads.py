"""Tests for the shared upload helpers."""

from __future__ import annotations

import io

import pytest
from fastapi import HTTPException

from uploads import safe_filename, save_upload


class FakeUpload:
    """Minimal stand-in for fastapi.UploadFile."""

    def __init__(self, data: bytes) -> None:
        self.file = io.BytesIO(data)


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("a/b/c.exe", "c.exe"),
        ("..\\..\\etc/evil.exe", "evil.exe"),
        ("..", "sample.bin"),
        ("", "sample.bin"),
        (None, "sample.bin"),
        ("x<y>.exe", "x_y_.exe"),
        ("a\x00b\x1f.bin", "a_b_.bin"),
    ],
)
def test_safe_filename(raw, expected) -> None:
    assert safe_filename(raw) == expected


def test_save_upload_writes_content_and_hardens_mode(tmp_path) -> None:
    dest = tmp_path / "nested" / "sample.bin"

    size = save_upload(FakeUpload(b"hello world"), dest, 1024, chunk_size=3)

    assert size == 11
    assert dest.read_bytes() == b"hello world"
    assert dest.parent.is_dir()
    assert dest.stat().st_mode & 0o777 == 0o600


def test_save_upload_over_limit_removes_partial_file(tmp_path) -> None:
    dest = tmp_path / "nested" / "too_big.bin"
    max_bytes = 1024 * 1024

    with pytest.raises(HTTPException) as exc_info:
        save_upload(FakeUpload(b"x" * (max_bytes + 1)), dest, max_bytes, chunk_size=512 * 1024)

    assert exc_info.value.status_code == 413
    assert exc_info.value.detail == "file exceeds 1 MB limit"
    assert not dest.exists()

"""Tests for the --serve non-loopback bind guard in main.py."""

from __future__ import annotations

import sys

import pytest

import main

LOOPBACK_HOSTS = ["127.0.0.1", "127.5.0.1", "localhost", "::1", "[::1]"]
NON_LOOPBACK_HOSTS = ["0.0.0.0", "::", "192.168.1.10", "example.com", ""]


class FakeUvicorn:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def run(self, app: object, host: str, port: int) -> None:
        self.calls.append({"app": app, "host": host, "port": port})


@pytest.fixture
def fake_uvicorn(monkeypatch) -> FakeUvicorn:
    import uvicorn

    fake = FakeUvicorn()
    monkeypatch.setattr(uvicorn, "run", fake.run)
    return fake


def run_main(monkeypatch, argv: list[str]) -> None:
    monkeypatch.setattr(sys, "argv", ["main.py", *argv])
    main.main()


@pytest.mark.parametrize("host", LOOPBACK_HOSTS)
def test_is_loopback_host_true(host: str) -> None:
    assert main.is_loopback_host(host) is True


@pytest.mark.parametrize("host", NON_LOOPBACK_HOSTS)
def test_is_loopback_host_false(host: str) -> None:
    assert main.is_loopback_host(host) is False


def test_serve_rejects_non_loopback_without_flag(monkeypatch, fake_uvicorn) -> None:
    with pytest.raises(SystemExit):
        run_main(monkeypatch, ["--serve", "--host", "0.0.0.0"])
    assert fake_uvicorn.calls == []


def test_serve_remote_bind_with_allow_remote(monkeypatch, fake_uvicorn) -> None:
    run_main(monkeypatch, ["--serve", "--host", "0.0.0.0", "--allow-remote"])
    assert len(fake_uvicorn.calls) == 1
    assert fake_uvicorn.calls[0]["host"] == "0.0.0.0"


def test_serve_default_host_is_loopback(monkeypatch, fake_uvicorn) -> None:
    run_main(monkeypatch, ["--serve"])
    assert len(fake_uvicorn.calls) == 1
    assert fake_uvicorn.calls[0]["host"] == "127.0.0.1"

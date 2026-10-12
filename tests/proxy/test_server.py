"""Tests for serve listen options: TLS files, loopback rule and a real HTTPS connection."""

import re
import socket
import ssl
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
import trustme
import uvicorn
from starlette.applications import Starlette

from claude_guard.config import Settings
from claude_guard.proxy.app import create_app
from claude_guard.proxy.server import (
    ServeConfigError,
    build_serve_config,
    is_loopback,
    uvicorn_config,
)


@pytest.fixture(scope="module")
def ca() -> trustme.CA:
    return trustme.CA()


@pytest.fixture
def tls_files(ca: trustme.CA, tmp_path: Path) -> tuple[Path, Path]:
    cert = ca.issue_cert("localhost", "127.0.0.1")
    certfile, keyfile = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert.cert_chain_pems[0].write_to_path(str(certfile))
    cert.private_key_pem.write_to_path(str(keyfile))
    return certfile, keyfile


# --- is_loopback ------------------------------------------------------------------


@pytest.mark.parametrize("host", ["127.0.0.1", "127.1.2.3", "::1", "[::1]", "localhost"])
def test_loopback_hosts(host: str) -> None:
    assert is_loopback(host)


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.10", "example.com", ""])
def test_non_loopback_hosts(host: str) -> None:
    assert not is_loopback(host)


# --- build_serve_config -----------------------------------------------------------


def test_default_is_plain_http_on_loopback() -> None:
    config = build_serve_config(Settings())
    assert (config.host, config.port, config.tls, config.insecure_bind) == (
        "127.0.0.1",
        8787,
        False,
        False,
    )
    assert config.base_url == "http://127.0.0.1:8787"


def test_refuses_plain_http_on_non_loopback() -> None:
    with pytest.raises(ServeConfigError, match="refusing to serve plain HTTP"):
        build_serve_config(Settings(), host="0.0.0.0")


def test_refuses_non_loopback_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARD_HOST", "192.168.1.10")
    with pytest.raises(ServeConfigError, match=re.escape("192.168.1.10")):
        build_serve_config(Settings())


def test_insecure_bind_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARD_ALLOW_INSECURE_BIND", "true")
    config = build_serve_config(Settings(), host="0.0.0.0")
    assert config.insecure_bind
    assert not config.tls


def test_tls_allows_non_loopback(tls_files: tuple[Path, Path]) -> None:
    certfile, keyfile = tls_files
    config = build_serve_config(
        Settings(),
        host="0.0.0.0",
        tls_certfile=certfile,
        tls_keyfile=keyfile,
    )
    assert config.tls
    assert not config.insecure_bind
    assert config.base_url == "https://0.0.0.0:8787"


def test_tls_from_env(monkeypatch: pytest.MonkeyPatch, tls_files: tuple[Path, Path]) -> None:
    certfile, keyfile = tls_files
    monkeypatch.setenv("GUARD_TLS_CERTFILE", str(certfile))
    monkeypatch.setenv("GUARD_TLS_KEYFILE", str(keyfile))
    config = build_serve_config(Settings())
    assert (config.tls_certfile, config.tls_keyfile) == (certfile, keyfile)


def test_cli_options_override_settings(
    monkeypatch: pytest.MonkeyPatch, tls_files: tuple[Path, Path]
) -> None:
    certfile, keyfile = tls_files
    monkeypatch.setenv("GUARD_TLS_CERTFILE", "/nonexistent/cert.pem")
    config = build_serve_config(
        Settings(), host="::1", port=9443, tls_certfile=certfile, tls_keyfile=keyfile
    )
    assert config.tls_certfile == certfile
    assert config.base_url == "https://[::1]:9443"


def test_requires_cert_and_key_together(tls_files: tuple[Path, Path]) -> None:
    certfile, _ = tls_files
    with pytest.raises(ServeConfigError, match="both a certificate and a key"):
        build_serve_config(Settings(), tls_certfile=certfile)


def test_missing_tls_file(tls_files: tuple[Path, Path], tmp_path: Path) -> None:
    certfile, _ = tls_files
    with pytest.raises(ServeConfigError, match="TLS file not found"):
        build_serve_config(Settings(), tls_certfile=certfile, tls_keyfile=tmp_path / "nope.pem")


def test_mismatched_key(ca: trustme.CA, tls_files: tuple[Path, Path], tmp_path: Path) -> None:
    certfile, _ = tls_files
    other_key = tmp_path / "other.pem"
    ca.issue_cert("localhost").private_key_pem.write_to_path(str(other_key))
    with pytest.raises(ServeConfigError, match="cannot load TLS certificate"):
        build_serve_config(Settings(), tls_certfile=certfile, tls_keyfile=other_key)


def test_uvicorn_config_passes_tls_files(tls_files: tuple[Path, Path]) -> None:
    certfile, keyfile = tls_files
    config = build_serve_config(Settings(), tls_certfile=certfile, tls_keyfile=keyfile)
    uv_config = uvicorn_config(Starlette(), config, "INFO")
    assert (uv_config.ssl_certfile, uv_config.ssl_keyfile) == (str(certfile), str(keyfile))
    assert uv_config.log_level == "info"


def test_uvicorn_config_without_tls() -> None:
    uv_config = uvicorn_config(Starlette(), build_serve_config(Settings()), "INFO")
    assert uv_config.ssl_certfile is None
    assert uv_config.ssl_keyfile is None


# --- real HTTPS connection --------------------------------------------------------


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


@pytest.fixture
def https_server(tls_files: tuple[Path, Path], repo_root: Path) -> Iterator[str]:
    certfile, keyfile = tls_files
    settings = Settings(policy_path=repo_root / "policy.yaml")
    config = build_serve_config(
        settings, port=free_port(), tls_certfile=certfile, tls_keyfile=keyfile
    )
    server = uvicorn.Server(uvicorn_config(create_app(settings), config, "WARNING"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        assert thread.is_alive(), "server failed to start"
        assert time.monotonic() < deadline, "server did not start in time"
        time.sleep(0.05)
    yield config.base_url.replace("127.0.0.1", "localhost")
    server.should_exit = True
    thread.join(timeout=10)


def test_https_connection(https_server: str, ca: trustme.CA) -> None:
    context = ssl.create_default_context()
    ca.configure_trust(context)
    response = httpx.get(f"{https_server}/healthz", verify=context)
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_https_rejects_untrusted_client(https_server: str) -> None:
    with pytest.raises(httpx.ConnectError, match="CERTIFICATE_VERIFY_FAILED"):
        httpx.get(f"{https_server}/healthz")


def test_plain_http_to_tls_port_fails(https_server: str) -> None:
    url = https_server.replace("https://", "http://")
    with pytest.raises(httpx.HTTPError):
        httpx.get(f"{url}/healthz")

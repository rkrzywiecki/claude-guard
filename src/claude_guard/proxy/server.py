"""Listen options for `serve`: TLS files and the no-plain-HTTP-outside-loopback rule."""

from __future__ import annotations

import ipaddress
import ssl
from pathlib import Path

import uvicorn
from pydantic import BaseModel, ConfigDict
from starlette.types import ASGIApp

from claude_guard.config import Settings


class ServeConfigError(Exception):
    """Raised when the listen options are unsafe or the TLS files are unusable."""


class ServeConfig(BaseModel):
    """Validated listen options for the proxy."""

    model_config = ConfigDict(frozen=True)

    host: str
    port: int
    tls_certfile: Path | None = None
    tls_keyfile: Path | None = None
    # True when plain HTTP is served on a non-loopback address (GUARD_ALLOW_INSECURE_BIND).
    insecure_bind: bool = False

    @property
    def tls(self) -> bool:
        return self.tls_certfile is not None

    @property
    def base_url(self) -> str:
        scheme = "https" if self.tls else "http"
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{scheme}://{host}:{self.port}"


def is_loopback(host: str) -> bool:
    """True for addresses reachable only from this machine (localhost, 127.0.0.0/8, ::1)."""
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def build_serve_config(
    settings: Settings,
    *,
    host: str | None = None,
    port: int | None = None,
    tls_certfile: Path | None = None,
    tls_keyfile: Path | None = None,
) -> ServeConfig:
    """Merge CLI options over settings and enforce the TLS rules."""
    resolved_host = host or settings.host
    certfile = tls_certfile or settings.tls_certfile
    keyfile = tls_keyfile or settings.tls_keyfile

    if (certfile is None) != (keyfile is None):
        raise ServeConfigError(
            "TLS needs both a certificate and a key: set GUARD_TLS_CERTFILE and "
            "GUARD_TLS_KEYFILE (or --tls-certfile and --tls-keyfile)"
        )
    if certfile is not None and keyfile is not None:
        _check_tls_files(certfile, keyfile)

    insecure = certfile is None and not is_loopback(resolved_host)
    if insecure and not settings.allow_insecure_bind:
        raise ServeConfigError(
            f"refusing to serve plain HTTP on non-loopback address {resolved_host!r}: prompts and "
            "API keys would cross the network unencrypted. Configure TLS (GUARD_TLS_CERTFILE, "
            "GUARD_TLS_KEYFILE), bind to 127.0.0.1, or set GUARD_ALLOW_INSECURE_BIND=true if TLS "
            "is terminated in front of the proxy"
        )

    return ServeConfig(
        host=resolved_host,
        port=port or settings.port,
        tls_certfile=certfile,
        tls_keyfile=keyfile,
        insecure_bind=insecure,
    )


def _check_tls_files(certfile: Path, keyfile: Path) -> None:
    # Load once up front so a bad file is a one-line error instead of a uvicorn traceback.
    for path in (certfile, keyfile):
        if not path.is_file():
            raise ServeConfigError(f"TLS file not found: {path}")
    try:
        ssl.create_default_context(ssl.Purpose.CLIENT_AUTH).load_cert_chain(certfile, keyfile)
    except (ssl.SSLError, OSError) as exc:
        raise ServeConfigError(
            f"cannot load TLS certificate {certfile} / key {keyfile}: {exc}"
        ) from exc


def uvicorn_config(app: ASGIApp, config: ServeConfig, log_level: str) -> uvicorn.Config:
    return uvicorn.Config(
        app,
        host=config.host,
        port=config.port,
        log_level=log_level.lower(),
        ssl_certfile=str(config.tls_certfile) if config.tls_certfile else None,
        ssl_keyfile=str(config.tls_keyfile) if config.tls_keyfile else None,
    )

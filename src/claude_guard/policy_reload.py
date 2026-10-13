"""Policy hot reload for the long-running proxy.

`PolicyReloader.check()` runs on every proxy request and, at most every
`GUARD_POLICY_RELOAD_INTERVAL` seconds, compares the policy file's modification time, size and
inode with the last version seen. `reload()` (also bound to SIGHUP) reads the file now.

A file that changed is parsed and validated first; only a valid policy replaces the running one
(`GuardEngine.reload_policy`). An invalid or missing file keeps the previous policy: protection
never drops because of a typo or a half-written file. The failure is logged once per file version
and counted; a later save is tried again. A save that leaves the content identical (same SHA-256)
changes nothing.

Hooks and `scan` read the policy on every run, so they need no reload.
"""

from __future__ import annotations

import hashlib
import os
import time
from collections.abc import Callable
from pathlib import Path

import structlog

from claude_guard.config import PolicyError, parse_policy
from claude_guard.engine import GuardEngine

log = structlog.get_logger(__name__)

Fingerprint = tuple[int, int, int]


def fingerprint(path: Path) -> Fingerprint | None:
    """(mtime in ns, size, inode), or None when the file cannot be read."""
    try:
        stat = os.stat(path)
    except OSError:
        return None
    return (stat.st_mtime_ns, stat.st_size, stat.st_ino)


def short_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:12]


class PolicyReloader:
    def __init__(
        self,
        engine: GuardEngine,
        path: Path,
        *,
        interval: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._engine = engine
        self._path = path
        self._interval = interval
        self._clock = clock
        self._next_check = clock() + interval
        self._seen = fingerprint(path)
        self._failed: Fingerprint | None = None
        try:
            # Identifies the running policy (in /healthz); None when the engine was given a policy
            # that does not come from this file.
            self.version: str | None = short_digest(path.read_bytes())
        except OSError:
            self.version = None
        self.reloads = 0
        self.errors = 0

    def check(self) -> bool:
        """Reload if the file changed since the last look; True when a new policy is active."""
        if self._interval <= 0:
            return False
        now = self._clock()
        if now < self._next_check:
            return False
        self._next_check = now + self._interval
        current = fingerprint(self._path)
        if current is None or current in (self._seen, self._failed):
            return False
        return self.reload()

    def reload(self) -> bool:
        """Read the file now; True when a new policy is active."""
        current = fingerprint(self._path)
        try:
            data = self._path.read_bytes()
            digest = short_digest(data)
            if digest == self.version:
                self._seen = current
                return False
            policy = parse_policy(data.decode("utf-8"), self._path)
        except (OSError, UnicodeDecodeError, PolicyError) as exc:
            if current is None or current != self._failed:
                self.errors += 1
                log.error(
                    "policy_reload_failed",
                    path=str(self._path),
                    error=str(exc),
                    message="keeping the previous policy",
                )
            self._failed = current
            return False
        self._engine.reload_policy(policy)
        self._seen = current
        self._failed = None
        previous, self.version = self.version, digest
        self.reloads += 1
        log.info("policy_reloaded", path=str(self._path), version=digest, previous=previous)
        return True

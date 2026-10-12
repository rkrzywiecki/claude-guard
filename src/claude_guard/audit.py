"""JSONL audit log writer (logs/audit.jsonl) with secret redaction.

Each inspection appends one JSON line. Free-text fields (excerpts, messages, errors, notes) are
passed through the secret scanner before writing, so a secret quoted next to an injection
pattern is still masked. Hooks run as separate processes, so every record is written with a
single append call, under an exclusive lock on `<audit>.lock` (POSIX) that also covers
rotation.

Rotation: when a record would grow the file past `max_bytes`, `audit.jsonl` becomes
`audit.jsonl.1`, `.1` becomes `.2`, and so on up to `backups`; the oldest is dropped.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

if sys.platform != "win32":
    import fcntl

import structlog
from pydantic import BaseModel, ConfigDict, Field

from claude_guard.detectors.secrets import SecretScanner
from claude_guard.models import Action, Category, Direction, Finding, Severity, Verdict

log = structlog.get_logger(__name__)


class AuditFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    detector: str
    category: Category
    rule: str
    severity: Severity
    action: Action
    confidence: float
    message: str
    location: str | None = None
    excerpt: str | None = None


class AuditRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    timestamp: datetime
    direction: Direction
    action: Action
    source: str | None = None
    session_id: str | None = None
    duration_ms: float | None = None
    error: str | None = None
    notes: list[str] = Field(default_factory=list)
    findings: list[AuditFinding] = Field(default_factory=list)


def audit_files(path: Path) -> list[Path]:
    """The audit log and its rotated copies, oldest first."""
    pattern = re.compile(rf"{re.escape(path.name)}\.(\d+)")
    rotated: list[tuple[int, Path]] = []
    if path.parent.is_dir():
        for candidate in path.parent.iterdir():
            match = pattern.fullmatch(candidate.name)
            if match:
                rotated.append((int(match.group(1)), candidate))
    files = [candidate for _, candidate in sorted(rotated, reverse=True)]
    return [*files, path] if path.exists() else files


@contextmanager
def _locked(lock_path: Path) -> Iterator[None]:
    if sys.platform == "win32":
        yield
        return
    with lock_path.open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


class AuditLog:
    """Appends redacted verdicts to a JSONL file, rotating it by size."""

    def __init__(
        self, path: Path, scanner: SecretScanner, *, max_bytes: int = 0, backups: int = 5
    ) -> None:
        self._path = path
        self._scanner = scanner
        self._max_bytes = max_bytes
        self._backups = backups

    @property
    def path(self) -> Path:
        return self._path

    def build_record(
        self,
        verdict: Verdict,
        *,
        source: str | None = None,
        session_id: str | None = None,
        duration_ms: float | None = None,
    ) -> AuditRecord:
        return AuditRecord(
            timestamp=datetime.now(UTC),
            direction=verdict.direction,
            action=verdict.action,
            source=source,
            session_id=session_id,
            duration_ms=round(duration_ms, 2) if duration_ms is not None else None,
            error=self._mask(verdict.error),
            notes=[self._scanner.mask(note) for note in verdict.notes],
            findings=[self._finding(finding) for finding in verdict.findings],
        )

    def record(
        self,
        verdict: Verdict,
        *,
        source: str | None = None,
        session_id: str | None = None,
        duration_ms: float | None = None,
    ) -> AuditRecord:
        """Write one record and return it. Failures are logged, never raised: auditing must not
        break traffic."""
        record = self.build_record(
            verdict, source=source, session_id=session_id, duration_ms=duration_ms
        )
        line = record.model_dump_json(exclude_none=True) + "\n"
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with _locked(self._path.with_name(f"{self._path.name}.lock")):
                self._rotate_if_needed(len(line.encode()))
                with self._path.open("a", encoding="utf-8") as handle:
                    handle.write(line)
        except OSError as exc:
            log.error("audit_write_failed", path=str(self._path), error=str(exc))
        return record

    def _rotate_if_needed(self, incoming: int) -> None:
        if not self._max_bytes:
            return
        try:
            size = self._path.stat().st_size
        except FileNotFoundError:
            return
        if size == 0 or size + incoming <= self._max_bytes:
            return
        for index in range(self._backups - 1, 0, -1):
            older = self._path.with_name(f"{self._path.name}.{index}")
            if older.exists():
                os.replace(older, self._path.with_name(f"{self._path.name}.{index + 1}"))
        os.replace(self._path, self._path.with_name(f"{self._path.name}.1"))

    def _finding(self, finding: Finding) -> AuditFinding:
        return AuditFinding(
            detector=finding.detector,
            category=finding.category,
            rule=finding.rule,
            severity=finding.severity,
            action=finding.action,
            confidence=finding.confidence,
            message=self._scanner.mask(finding.message),
            location=finding.location,
            excerpt=self._mask(finding.excerpt),
        )

    def _mask(self, text: str | None) -> str | None:
        return self._scanner.mask(text) if text is not None else None

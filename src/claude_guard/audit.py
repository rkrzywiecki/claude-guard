"""JSONL audit log writer (logs/audit.jsonl) with secret redaction.

Each inspection appends one JSON line. Free-text fields (excerpts, messages, errors, notes) are
passed through the secret scanner before writing, so a secret quoted next to an injection
pattern is still masked. Hooks run as separate processes, so every record is written with a
single append call.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

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


class AuditLog:
    """Appends redacted verdicts to a JSONL file."""

    def __init__(self, path: Path, scanner: SecretScanner) -> None:
        self._path = path
        self._scanner = scanner

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
    ) -> None:
        """Write one record. Failures are logged, never raised: auditing must not break traffic."""
        record = self.build_record(
            verdict, source=source, session_id=session_id, duration_ms=duration_ms
        )
        line = record.model_dump_json(exclude_none=True) + "\n"
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(line)
        except OSError as exc:
            log.error("audit_write_failed", path=str(self._path), error=str(exc))

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

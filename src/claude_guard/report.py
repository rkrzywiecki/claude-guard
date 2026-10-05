"""Audit log summaries for `claude-guard report`."""

from __future__ import annotations

import re
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import BaseModel, Field, ValidationError

from claude_guard.audit import AuditRecord
from claude_guard.models import Action

_DURATION = re.compile(r"^\s*(\d+)\s*([smhdw])\s*$")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}


def parse_since(value: str, now: datetime | None = None) -> datetime:
    """Parse `30m`, `24h`, `7d`, `2w` (relative) or an ISO 8601 timestamp (absolute)."""
    now = now or datetime.now(UTC)
    match = _DURATION.match(value)
    if match:
        amount, unit = int(match.group(1)), match.group(2)
        return now - timedelta(**{_UNITS[unit]: amount})
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(
            f"invalid --since {value!r}: use e.g. 30m, 24h, 7d, 2w or an ISO timestamp"
        ) from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


class RuleCount(BaseModel):
    category: str
    rule: str
    count: int


class Report(BaseModel):
    since: datetime
    until: datetime
    total: int = 0
    skipped_lines: int = 0
    by_action: dict[str, int] = Field(default_factory=dict)
    by_direction: dict[str, dict[str, int]] = Field(default_factory=dict)
    by_source: dict[str, int] = Field(default_factory=dict)
    top_rules: list[RuleCount] = Field(default_factory=list)
    top_blocked_sessions: dict[str, int] = Field(default_factory=dict)
    errors: int = 0
    duration_ms_avg: float | None = None
    duration_ms_p95: float | None = None


def load_records(path: Path, since: datetime) -> tuple[list[AuditRecord], int]:
    """Read records at or after `since`; returns (records, number of unreadable lines)."""
    records: list[AuditRecord] = []
    skipped = 0
    if not path.exists():
        return records, skipped
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                record = AuditRecord.model_validate_json(line)
            except ValidationError:
                skipped += 1
                continue
            if record.timestamp >= since:
                records.append(record)
    return records, skipped


def summarize(
    records: list[AuditRecord],
    since: datetime,
    until: datetime | None = None,
    skipped: int = 0,
    top: int = 10,
) -> Report:
    report = Report(since=since, until=until or datetime.now(UTC), skipped_lines=skipped)
    report.total = len(records)

    actions: Counter[str] = Counter()
    directions: dict[str, Counter[str]] = {}
    sources: Counter[str] = Counter()
    rules: Counter[tuple[str, str]] = Counter()
    blocked_sessions: Counter[str] = Counter()
    durations: list[float] = []

    for record in records:
        actions[record.action.value] += 1
        directions.setdefault(record.direction.value, Counter())[record.action.value] += 1
        sources[record.source or "unknown"] += 1
        if record.error:
            report.errors += 1
        if record.action is Action.BLOCK and record.session_id:
            blocked_sessions[record.session_id] += 1
        if record.duration_ms is not None:
            durations.append(record.duration_ms)
        for finding in record.findings:
            if finding.action is not Action.ALLOW:
                rules[(finding.category.value, finding.rule)] += 1

    report.by_action = {action.value: actions[action.value] for action in Action}
    report.by_direction = {d: dict(c) for d, c in sorted(directions.items())}
    report.by_source = dict(sources.most_common())
    report.top_rules = [
        RuleCount(category=category, rule=rule, count=count)
        for (category, rule), count in rules.most_common(top)
    ]
    report.top_blocked_sessions = dict(blocked_sessions.most_common(top))
    if durations:
        ordered = sorted(durations)
        report.duration_ms_avg = round(sum(ordered) / len(ordered), 2)
        report.duration_ms_p95 = ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))]
    return report

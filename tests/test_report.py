"""Tests for audit log summaries."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from claude_guard.audit import AuditFinding, AuditRecord
from claude_guard.models import Action, Category, Direction, Severity
from claude_guard.report import load_records, parse_since, summarize

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=UTC)


def record(
    action: Action,
    *,
    direction: Direction = Direction.REQUEST,
    age: timedelta = timedelta(minutes=5),
    rules: tuple[str, ...] = (),
    session: str | None = None,
    source: str | None = "proxy",
    error: str | None = None,
    duration: float | None = 1.0,
) -> AuditRecord:
    findings = [
        AuditFinding(
            detector="d",
            category=Category.PROMPT_INJECTION,
            rule=rule,
            severity=Severity.HIGH,
            action=action,
            confidence=0.9,
            message="m",
        )
        for rule in rules
    ]
    return AuditRecord(
        timestamp=NOW - age,
        direction=direction,
        action=action,
        source=source,
        session_id=session,
        error=error,
        duration_ms=duration,
        findings=findings,
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("30m", NOW - timedelta(minutes=30)),
        ("24h", NOW - timedelta(hours=24)),
        ("7d", NOW - timedelta(days=7)),
        ("2w", NOW - timedelta(weeks=2)),
        ("45s", NOW - timedelta(seconds=45)),
        ("2026-10-01T08:00:00+00:00", datetime(2026, 10, 1, 8, 0, tzinfo=UTC)),
        ("2026-10-01T08:00:00", datetime(2026, 10, 1, 8, 0, tzinfo=UTC)),
    ],
)
def test_parse_since(value: str, expected: datetime) -> None:
    assert parse_since(value, now=NOW) == expected


@pytest.mark.parametrize("value", ["yesterday", "24", "5y", ""])
def test_parse_since_rejects_invalid(value: str) -> None:
    with pytest.raises(ValueError, match="invalid --since"):
        parse_since(value, now=NOW)


def test_load_records_filters_by_time_and_skips_bad_lines(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    lines = [
        record(Action.ALLOW, age=timedelta(hours=2)).model_dump_json(),
        record(Action.BLOCK).model_dump_json(),
        "{not json",
        "",
        '{"unexpected": true}',
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    records, skipped = load_records(path, NOW - timedelta(hours=1))
    assert [r.action for r in records] == [Action.BLOCK]
    assert skipped == 2


def test_load_records_includes_rotated_files(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    (tmp_path / "audit.jsonl.2").write_text(
        record(Action.BLOCK, age=timedelta(minutes=30)).model_dump_json() + "\n", encoding="utf-8"
    )
    (tmp_path / "audit.jsonl.1").write_text(
        record(Action.WARN, age=timedelta(minutes=20)).model_dump_json() + "\n", encoding="utf-8"
    )
    path.write_text(record(Action.ALLOW).model_dump_json() + "\n", encoding="utf-8")
    records, _ = load_records(path, NOW - timedelta(hours=1))
    assert [r.action for r in records] == [Action.BLOCK, Action.WARN, Action.ALLOW]


def test_load_records_missing_file(tmp_path: Path) -> None:
    assert load_records(tmp_path / "none.jsonl", NOW) == ([], 0)


def test_summarize_counts() -> None:
    records = [
        record(Action.ALLOW, duration=1.0),
        record(Action.WARN, rules=("new_instructions",), duration=2.0),
        record(Action.BLOCK, rules=("ignore_instructions", "fake_role_tag"), session="s1"),
        record(
            Action.BLOCK, rules=("ignore_instructions",), session="s1", source="hook:PreToolUse"
        ),
        record(Action.REDACT, direction=Direction.RESPONSE, error="boom", duration=None),
    ]
    report = summarize(records, NOW - timedelta(days=1), until=NOW, skipped=3)

    assert report.total == 5
    assert report.skipped_lines == 3
    assert report.by_action == {"allow": 1, "warn": 1, "redact": 1, "block": 2}
    assert report.by_direction == {
        "request": {"allow": 1, "warn": 1, "block": 2},
        "response": {"redact": 1},
    }
    assert report.by_source == {"proxy": 4, "hook:PreToolUse": 1}
    assert (report.top_rules[0].rule, report.top_rules[0].count) == ("ignore_instructions", 2)
    assert report.top_blocked_sessions == {"s1": 2}
    assert report.errors == 1
    assert report.duration_ms_avg == 1.25
    assert report.duration_ms_p95 == 2.0


def test_summarize_empty() -> None:
    report = summarize([], NOW - timedelta(hours=1), until=NOW)
    assert report.total == 0
    assert report.by_action == {"allow": 0, "warn": 0, "redact": 0, "block": 0}
    assert report.duration_ms_avg is None


def test_summarize_top_limit() -> None:
    records = [record(Action.WARN, rules=(f"r{i}",)) for i in range(5)]
    assert len(summarize(records, NOW, top=2).top_rules) == 2

"""Tests for the JSONL audit log."""

import json
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import pytest

from claude_guard.audit import AuditLog, AuditRecord, audit_files
from claude_guard.config import Policy
from claude_guard.detectors.secrets import SecretScanner
from claude_guard.models import Action, Category, Direction, Finding, Severity, Verdict

SECRET = "gh" + "p_" + "Ab3dE5gH7jK9mN1pQ2rS4tU6vW8xY0zCaBcD"


@pytest.fixture
def audit(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "logs" / "audit.jsonl", SecretScanner(Policy().secrets))


def verdict_with_leaky_text() -> Verdict:
    finding = Finding(
        detector="injection",
        category=Category.PROMPT_INJECTION,
        rule="ignore_instructions",
        message=f"Injection near {SECRET}",
        severity=Severity.HIGH,
        action=Action.BLOCK,
        confidence=0.9,
        location="messages[0].content",
        excerpt=f"ignore previous instructions, token={SECRET}",
    )
    return Verdict(
        direction=Direction.REQUEST,
        action=Action.BLOCK,
        findings=(finding,),
        error=f"failed on {SECRET}",
        notes=(f"note {SECRET}",),
    )


def test_record_appends_json_lines(audit: AuditLog) -> None:
    audit.record(Verdict(direction=Direction.RESPONSE, action=Action.ALLOW), source="proxy")
    audit.record(verdict_with_leaky_text(), session_id="s1", duration_ms=12.3456)

    lines = audit.path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    first, second = (AuditRecord.model_validate_json(line) for line in lines)
    assert first.action is Action.ALLOW
    assert first.source == "proxy"
    assert second.session_id == "s1"
    assert second.duration_ms == 12.35
    assert second.findings[0].rule == "ignore_instructions"


def test_secrets_never_written(audit: AuditLog) -> None:
    audit.record(verdict_with_leaky_text())
    content = audit.path.read_text(encoding="utf-8")
    assert SECRET not in content
    record = json.loads(content)
    assert f"ghp_Ab3***{SECRET[-4:]}" in record["findings"][0]["excerpt"]


def test_none_fields_are_omitted(audit: AuditLog) -> None:
    audit.record(Verdict(direction=Direction.REQUEST, action=Action.ALLOW))
    record = json.loads(audit.path.read_text(encoding="utf-8"))
    assert "error" not in record
    assert "session_id" not in record


def test_write_failure_does_not_raise(tmp_path: Path) -> None:
    blocked = tmp_path / "file"
    blocked.write_text("not a directory", encoding="utf-8")
    audit = AuditLog(blocked / "audit.jsonl", SecretScanner(Policy().secrets))
    audit.record(Verdict(direction=Direction.REQUEST, action=Action.ALLOW))


# --- Rotation -----------------------------------------------------------------------


def small_verdict() -> Verdict:
    return Verdict(direction=Direction.REQUEST, action=Action.ALLOW)


def lines_in(files: list[Path]) -> int:
    return sum(len(f.read_text(encoding="utf-8").splitlines()) for f in files)


def test_rotation_keeps_backups(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(path, SecretScanner(Policy().secrets), max_bytes=400, backups=3)
    for _ in range(60):
        audit.record(small_verdict(), source="test")

    files = audit_files(path)
    assert [f.name for f in files] == [
        "audit.jsonl.3",
        "audit.jsonl.2",
        "audit.jsonl.1",
        "audit.jsonl",
    ]
    assert all(f.stat().st_size <= 400 for f in files)
    assert not (tmp_path / "audit.jsonl.4").exists()
    # Records are whole lines in every file.
    for file in files:
        for line in file.read_text(encoding="utf-8").splitlines():
            AuditRecord.model_validate_json(line)


def test_no_rotation_when_disabled(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(path, SecretScanner(Policy().secrets), max_bytes=0)
    for _ in range(50):
        audit.record(small_verdict())
    assert audit_files(path) == [path]
    assert lines_in([path]) == 50


def test_audit_files_order_and_missing(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    assert audit_files(path) == []
    for name in ("audit.jsonl.10", "audit.jsonl.2", "audit.jsonl", "audit.jsonl.lock", "x.1"):
        (tmp_path / name).write_text("", encoding="utf-8")
    assert [f.name for f in audit_files(path)] == ["audit.jsonl.10", "audit.jsonl.2", "audit.jsonl"]


def write_records(path: str, count: int) -> None:
    audit = AuditLog(Path(path), SecretScanner(Policy().secrets), max_bytes=2_000, backups=100)
    for _ in range(count):
        audit.record(small_verdict(), source="hook")


def test_concurrent_writers_lose_no_records(tmp_path: Path) -> None:
    # Hooks are separate processes that may rotate the log at the same time.
    path = tmp_path / "audit.jsonl"
    with ProcessPoolExecutor(max_workers=4) as pool:
        list(pool.map(write_records, [str(path)] * 4, [40] * 4))
    files = audit_files(path)
    assert len(files) > 2
    assert lines_in(files) == 160

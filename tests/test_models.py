"""Tests for core data models."""

import pytest
from pydantic import ValidationError

from claude_guard.models import (
    Action,
    Category,
    Direction,
    Finding,
    InspectionContext,
    Severity,
    Span,
    TextSegment,
    Verdict,
)


def make_finding(action: Action, message: str = "issue") -> Finding:
    return Finding(
        detector="test",
        category=Category.SECRETS,
        rule="test-rule",
        message=message,
        severity=Severity.HIGH,
        action=action,
    )


def test_strictest_action_ordering() -> None:
    assert Action.strictest([Action.WARN, Action.BLOCK, Action.REDACT]) is Action.BLOCK
    assert Action.strictest([Action.WARN, Action.REDACT]) is Action.REDACT
    assert Action.strictest([Action.ALLOW, Action.WARN]) is Action.WARN
    assert Action.strictest([]) is Action.ALLOW


def test_severity_rank() -> None:
    assert Severity.LOW.rank < Severity.MEDIUM.rank < Severity.HIGH.rank < Severity.CRITICAL.rank


def test_verdict_from_findings_uses_strictest_action() -> None:
    verdict = Verdict.from_findings(
        Direction.REQUEST,
        [make_finding(Action.WARN, "minor"), make_finding(Action.BLOCK, "major")],
    )
    assert verdict.action is Action.BLOCK
    assert verdict.blocked
    assert verdict.reason == "[secrets] major"


def test_verdict_without_findings_allows() -> None:
    verdict = Verdict.from_findings(Direction.RESPONSE, [])
    assert verdict.action is Action.ALLOW
    assert not verdict.blocked
    assert verdict.reason == ""


def test_verdict_reason_reports_error() -> None:
    verdict = Verdict(direction=Direction.REQUEST, action=Action.BLOCK, error="timeout")
    assert verdict.reason == "guard error: timeout"


def test_finding_confidence_bounds() -> None:
    with pytest.raises(ValidationError):
        Finding(
            detector="test",
            category=Category.SECRETS,
            rule="r",
            message="m",
            severity=Severity.LOW,
            action=Action.WARN,
            confidence=1.5,
        )


def test_span_rejects_reversed_range() -> None:
    with pytest.raises(ValidationError):
        Span(start=5, end=2)


def test_context_untrusted_segments() -> None:
    ctx = InspectionContext(
        direction=Direction.REQUEST,
        segments=(
            TextSegment(location="system", text="be helpful"),
            TextSegment(location="messages[1].content[0]", text="tool says hi", trusted=False),
        ),
    )
    assert [s.location for s in ctx.untrusted_segments] == ["messages[1].content[0]"]


def test_models_are_immutable() -> None:
    finding = make_finding(Action.WARN)
    with pytest.raises(ValidationError):
        finding.message = "changed"  # type: ignore[misc]

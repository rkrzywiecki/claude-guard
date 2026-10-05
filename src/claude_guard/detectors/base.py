"""Detector protocol shared by all detectors, plus helpers for building findings."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from claude_guard.config import CategoryPolicy
from claude_guard.models import (
    Action,
    Category,
    Direction,
    Finding,
    InspectionContext,
    Severity,
    Span,
    TextSegment,
)

SNIPPET_CONTEXT = 40
SNIPPET_MAX = 160


@runtime_checkable
class Detector(Protocol):
    """A detector inspects one context and reports findings.

    Detectors must be independent of each other (the engine runs them concurrently) and must
    never put raw secret values in `Finding.excerpt`.
    """

    name: str

    async def detect(self, ctx: InspectionContext) -> list[Finding]: ...


def mask_secret(value: str) -> str:
    """Return a preview safe for logs, e.g. `sk-ant-***abcd`."""
    value = value.strip()
    prefix = value[: min(7, len(value) // 4)]
    suffix = value[-4:] if len(value) >= 16 else ""
    return f"{prefix}***{suffix}"


def snippet(text: str, start: int, end: int) -> str:
    """Return the matched text with some surrounding context, on one line and length-capped."""
    left = max(0, start - SNIPPET_CONTEXT)
    right = min(len(text), end + SNIPPET_CONTEXT)
    excerpt = " ".join(text[left:right].split())
    if len(excerpt) > SNIPPET_MAX:
        excerpt = excerpt[: SNIPPET_MAX - 3] + "..."
    prefix = "..." if left > 0 else ""
    suffix = "..." if right < len(text) else ""
    return f"{prefix}{excerpt}{suffix}"


def build_finding(
    *,
    detector: str,
    category: Category,
    policy: CategoryPolicy,
    direction: Direction,
    rule: str,
    message: str,
    severity: Severity,
    confidence: float,
    segment: TextSegment | None = None,
    span: Span | None = None,
    excerpt: str | None = None,
    replacement: str | None = None,
) -> Finding | None:
    """Create a finding with its action resolved by the category policy.

    Returns None when the policy maps the finding to `allow` (disabled category or severity
    below `min_severity`), so callers can simply skip it.
    """
    confidence = max(0.0, min(1.0, confidence))
    action = policy.resolve_action(direction, confidence, severity)
    if action is Action.ALLOW:
        return None
    return Finding(
        detector=detector,
        category=category,
        rule=rule,
        message=message,
        severity=severity,
        action=action,
        confidence=confidence,
        location=segment.location if segment else None,
        span=span,
        excerpt=excerpt,
        replacement=replacement,
    )

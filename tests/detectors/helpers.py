"""Helpers for building inspection contexts in detector tests."""

from claude_guard.detectors.base import Detector
from claude_guard.models import Direction, Finding, InspectionContext, TextSegment


def text_ctx(
    text: str,
    *,
    direction: Direction = Direction.REQUEST,
    role: str | None = "user",
    trusted: bool = True,
) -> InspectionContext:
    segment = TextSegment(
        location="messages[0].content[0].text", text=text, role=role, trusted=trusted
    )
    return InspectionContext(direction=direction, segments=(segment,))


def tool_ctx(
    tool_name: str, field: str, value: str, *, direction: Direction = Direction.TOOL_INPUT
) -> InspectionContext:
    segment = TextSegment(
        location=f"tool_input.{field}",
        text=value,
        role="assistant",
        tool_name=tool_name,
        tool_field=field,
    )
    return InspectionContext(direction=direction, segments=(segment,), tool_name=tool_name)


async def rules(detector: Detector, ctx: InspectionContext) -> list[str]:
    return [finding.rule for finding in await detector.detect(ctx)]


async def findings(detector: Detector, ctx: InspectionContext) -> list[Finding]:
    return await detector.detect(ctx)

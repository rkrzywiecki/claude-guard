"""Per-tool policy: deny, allow and warn lists of tool name globs (`tools` in policy.yaml).

Works on the tool calls recorded during extraction, so a call without arguments
(`mcp__server__list({})`) is covered too. Only tool calls about to run are checked: tool inputs
(hooks) and tool_use blocks in responses (proxy). Tool calls in a request are history.
"""

from __future__ import annotations

from fnmatch import fnmatchcase

from claude_guard.config import Policy
from claude_guard.detectors.base import build_finding
from claude_guard.models import (
    Action,
    Category,
    Direction,
    Finding,
    InspectionContext,
    Severity,
)

CHECKED_DIRECTIONS = frozenset({Direction.TOOL_INPUT, Direction.RESPONSE})


def _matches(name: str, globs: list[str]) -> bool:
    return any(fnmatchcase(name, glob) for glob in globs)


class ToolPolicyDetector:
    """Blocks or reports tool calls according to the `tools` policy."""

    name = "tools"

    def __init__(self, policy: Policy) -> None:
        self._policy = policy.tools

    async def detect(self, ctx: InspectionContext) -> list[Finding]:
        if ctx.direction not in CHECKED_DIRECTIONS:
            return []
        findings: list[Finding] = []
        for call in ctx.tool_calls:
            if _matches(call.name, self._policy.deny):
                rule, message, warn_only = "tool_denied", f"Tool {call.name} is denied", False
            elif self._policy.allow and not _matches(call.name, self._policy.allow):
                rule, message = "tool_not_allowed", f"Tool {call.name} is not in the allow list"
                warn_only = False
            elif _matches(call.name, self._policy.warn):
                rule, message, warn_only = "tool_watched", f"Tool {call.name} was called", True
            else:
                continue
            finding = build_finding(
                detector=self.name,
                category=Category.TOOLS,
                policy=self._policy,
                direction=ctx.direction,
                rule=rule,
                message=message,
                severity=Severity.LOW if warn_only else Severity.HIGH,
                confidence=1.0,
                location=call.location,
                excerpt=call.name,
            )
            if finding and warn_only and finding.action is not Action.WARN:
                finding = finding.model_copy(update={"action": Action.WARN})
            if finding:
                findings.append(finding)
        return findings

"""Data models: Verdict, Finding, Severity, Action, Direction."""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator


class Severity(StrEnum):
    """How serious a finding is, independent of the action taken."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


class Action(StrEnum):
    """What the guard does about a finding. Ordered from mildest to strictest."""

    ALLOW = "allow"
    WARN = "warn"
    REDACT = "redact"
    BLOCK = "block"

    @property
    def rank(self) -> int:
        return _ACTION_RANK[self]

    @classmethod
    def strictest(cls, actions: Iterable[Action]) -> Action:
        """Return the strictest action (block > redact > warn > allow), or allow if empty."""
        return max(actions, key=lambda action: action.rank, default=cls.ALLOW)


_ACTION_RANK = {Action.ALLOW: 0, Action.WARN: 1, Action.REDACT: 2, Action.BLOCK: 3}


class Direction(StrEnum):
    """Where the inspected content flows."""

    REQUEST = "request"
    RESPONSE = "response"
    TOOL_INPUT = "tool_input"
    TOOL_OUTPUT = "tool_output"


class Category(StrEnum):
    """Policy categories. Each finding belongs to exactly one."""

    SECRETS = "secrets"
    PROMPT_INJECTION = "prompt_injection"
    DANGEROUS_COMMANDS = "dangerous_commands"
    DATA_EXFILTRATION = "data_exfiltration"
    LLM_JUDGE = "llm_judge"


# Roles whose content comes from the operator (system prompt, tool definitions), not from users
# or tools. Injection heuristics and the LLM judge do not inspect them.
OPERATOR_ROLES = frozenset({"system", "tool_definition"})


class Span(BaseModel):
    """Half-open character range [start, end) within a text segment."""

    model_config = ConfigDict(frozen=True)

    start: int = Field(ge=0)
    end: int = Field(ge=0)

    @model_validator(mode="after")
    def _check_order(self) -> Span:
        if self.end < self.start:
            raise ValueError("span end must not precede start")
        return self


class TextSegment(BaseModel):
    """A piece of text extracted from a payload, with its origin.

    `location` is a JSON-path-like pointer into the payload (e.g. `messages[2].content[0].text`)
    so findings can be traced back and redactions applied in place. Segments taken from a tool
    call input carry `tool_name` and `tool_field` (e.g. `Bash` / `command`). Untrusted segments
    (tool results, fetched content) are where indirect prompt injection is expected.
    """

    model_config = ConfigDict(frozen=True)

    location: str
    text: str
    role: str | None = None
    trusted: bool = True
    tool_name: str | None = None
    tool_field: str | None = None


class InspectionContext(BaseModel):
    """Everything a detector needs to inspect one payload."""

    model_config = ConfigDict(frozen=True)

    direction: Direction
    segments: tuple[TextSegment, ...] = ()
    tool_name: str | None = None
    tool_input: dict[str, JsonValue] | None = None
    session_id: str | None = None
    notes: tuple[str, ...] = ()
    # Working directory of a tool call (from Claude Code hooks), for resolving relative paths.
    cwd: str | None = None

    @property
    def untrusted_segments(self) -> tuple[TextSegment, ...]:
        return tuple(segment for segment in self.segments if not segment.trusted)


class Finding(BaseModel):
    """A single issue reported by a detector.

    `excerpt` must never contain a raw secret: detectors store a redacted preview only.
    """

    model_config = ConfigDict(frozen=True)

    detector: str
    category: Category
    rule: str
    message: str
    severity: Severity
    action: Action
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    location: str | None = None
    span: Span | None = None
    excerpt: str | None = None
    replacement: str | None = None


class Verdict(BaseModel):
    """Aggregated result of inspecting one payload."""

    model_config = ConfigDict(frozen=True)

    direction: Direction
    action: Action
    findings: tuple[Finding, ...] = ()
    error: str | None = None
    notes: tuple[str, ...] = ()

    @classmethod
    def from_findings(
        cls, direction: Direction, findings: Iterable[Finding], notes: Iterable[str] = ()
    ) -> Verdict:
        collected = tuple(findings)
        return cls(
            direction=direction,
            action=Action.strictest(finding.action for finding in collected),
            findings=collected,
            notes=tuple(notes),
        )

    @property
    def blocked(self) -> bool:
        return self.action is Action.BLOCK

    @property
    def reason(self) -> str:
        """Human-readable summary of the findings that drove the verdict."""
        if self.error:
            return f"guard error: {self.error}"
        driving = [finding for finding in self.findings if finding.action is self.action]
        return "; ".join(f"[{f.category}] {f.message}" for f in driving)

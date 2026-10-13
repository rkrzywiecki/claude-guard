"""Inspection cache for requests: findings per request unit, reused on later requests.

A request carries the whole conversation, so in a session every message is inspected again on
every turn: the proxy's cost grows with the context (`claude-guard bench`). The heuristic
detectors look at one unit at a time (a message, a tool definition, the system prompt; phrases
split across blocks are matched within one message), so the findings of a unit depend only on
that unit's extracted segments and tool calls. The engine caches them under a hash of those,
and runs the detectors only on units it has not seen.

Keys hash the extracted segments, not the raw JSON: a segment also carries context from other
parts of the payload (the tool name of a `tool_result` comes from the matching `tool_use`), and
the location, which includes the message index. Cached findings are the raw detector output,
before the engine caps history findings at `warn`. The cache belongs to one engine and so to one
policy; it holds hashes and findings (masked excerpts), never the inspected text.
"""

from __future__ import annotations

import hashlib
import re
from collections import OrderedDict
from collections.abc import Iterable

from claude_guard.models import Finding, TextSegment, ToolCall

_UNIT = re.compile(r"(?:messages|tools)\[\d+\]|[^.\[]+")


def inspection_unit(location: str) -> str:
    """The top-level part of a request that `location` belongs to (`messages[3]`, `tools[0]`,
    `system`)."""
    match = _UNIT.match(location)
    return match.group() if match else location


def unit_key(items: Iterable[TextSegment | ToolCall]) -> str:
    digest = hashlib.sha256()
    for item in items:
        digest.update(type(item).__name__.encode())
        digest.update(item.model_dump_json().encode())
        digest.update(b"\0")  # never inside JSON text
    return digest.hexdigest()


class InspectionCache:
    """Least-recently-used map from unit keys to findings."""

    def __init__(self, max_entries: int) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be at least 1")
        self._max_entries = max_entries
        self._entries: OrderedDict[str, tuple[Finding, ...]] = OrderedDict()
        self.hits = 0
        self.misses = 0

    def __len__(self) -> int:
        return len(self._entries)

    def get(self, key: str) -> tuple[Finding, ...] | None:
        findings = self._entries.get(key)
        if findings is None:
            self.misses += 1
            return None
        self.hits += 1
        self._entries.move_to_end(key)
        return findings

    def put(self, key: str, findings: Iterable[Finding]) -> None:
        self._entries[key] = tuple(findings)
        self._entries.move_to_end(key)
        while len(self._entries) > self._max_entries:
            self._entries.popitem(last=False)

    def clear(self) -> None:
        self._entries.clear()

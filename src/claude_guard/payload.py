"""Text extraction from Messages API payloads and in-place redaction.

Payload shapes per direction:
- `request`: a Messages API request body (`system`, `messages`, `tools`, ...).
- `response`: a Messages API response (`content` blocks from the assistant).
- `tool_input`: `{"tool_name": str, "tool_input": {...}, "cwd": str?}` (a tool call about to run).
- `tool_output`: `{"tool_name": str, "tool_response": ...}` (a tool result, untrusted).

Every segment records its `location`, a path such as `messages[2].content[0].text`, built and
parsed by `format_path` / `parse_path`, so redactions can be written back to the same string.
"""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

from pydantic import JsonValue

from claude_guard.models import Direction, Finding, TextSegment

JsonObject = dict[str, JsonValue]
PathPart = str | int

# Keys inside blocks that hold identifiers, binary data or signatures rather than prose.
NON_TEXT_KEYS = frozenset(
    {
        "type",
        "id",
        "tool_use_id",
        "media_type",
        "signature",
        "encrypted_content",
        "encrypted_index",
        "cache_control",
        "citations",
        "page_age",
    }
)
SKIPPED_BLOCKS = frozenset({"image", "thinking", "redacted_thinking"})
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")


class PayloadError(ValueError):
    """The payload does not have the shape expected for its direction."""


# --- Paths ------------------------------------------------------------------------


def format_path(parts: Iterable[PathPart]) -> str:
    out = ""
    for part in parts:
        if isinstance(part, int):
            out += f"[{part}]"
        elif _IDENTIFIER.fullmatch(part):
            out += f".{part}" if out else part
        else:
            out += f"[{json.dumps(part)}]"
    return out


def parse_path(path: str) -> list[PathPart]:
    parts: list[PathPart] = []
    decoder = json.JSONDecoder()
    index = 0
    while index < len(path):
        char = path[index]
        if char == ".":
            index += 1
            continue
        if char == "[":
            if path.startswith('["', index):
                key, end = decoder.raw_decode(path, index + 1)
                parts.append(str(key))
                index = end + 1
            else:
                end = path.index("]", index)
                parts.append(int(path[index + 1 : end]))
                index = end + 1
            continue
        match = _IDENTIFIER.match(path, index)
        if not match:
            raise PayloadError(f"invalid path {path!r}")
        parts.append(match.group())
        index = match.end()
    return parts


# --- Extraction -------------------------------------------------------------------


@dataclass
class Extraction:
    segments: list[TextSegment] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    # Index of the first message that belongs to the current turn (after the last assistant
    # message). Segments in earlier messages are history.
    current_turn_start: int = 0

    def is_historical(self, location: str | None) -> bool:
        if location is None or not location.startswith("messages["):
            return False
        parts = parse_path(location)
        return isinstance(parts[1], int) and parts[1] < self.current_turn_start


def detect_direction(payload: JsonObject) -> Direction:
    """Guess the direction from the payload shape (used by `claude-guard scan`)."""
    if "messages" in payload:
        return Direction.REQUEST
    if "tool_response" in payload:
        return Direction.TOOL_OUTPUT
    if "tool_input" in payload:
        return Direction.TOOL_INPUT
    if "content" in payload and payload.get("role", "assistant") == "assistant":
        return Direction.RESPONSE
    raise PayloadError(
        "cannot detect the payload direction; pass --direction "
        "(request, response, tool_input or tool_output)"
    )


def extract(direction: Direction, payload: JsonObject) -> Extraction:
    """Collect every inspectable piece of text in `payload`."""
    extraction = Extraction()
    if direction is Direction.REQUEST:
        _extract_request(payload, extraction)
    elif direction is Direction.RESPONSE:
        _extract_blocks(payload.get("content"), ["content"], "assistant", True, extraction)
    elif direction is Direction.TOOL_INPUT:
        tool_name = _require_str(payload, "tool_name")
        tool_input = payload.get("tool_input")
        if not isinstance(tool_input, dict):
            raise PayloadError("tool_input must be an object")
        _extract_tool_input(tool_input, ["tool_input"], tool_name, extraction)
    else:
        # The tool name is validated but not attached: tool output is data, not a tool call.
        _require_str(payload, "tool_name")
        for path, text in _strings(payload.get("tool_response"), ["tool_response"]):
            extraction.segments.append(
                TextSegment(location=format_path(path), text=text, role="tool", trusted=False)
            )
    return extraction


def _extract_request(payload: JsonObject, extraction: Extraction) -> None:
    system = payload.get("system")
    if isinstance(system, str):
        _add(extraction, ["system"], system, "system", True)
    elif isinstance(system, list):
        _extract_blocks(system, ["system"], "system", True, extraction)

    tools = payload.get("tools")
    if isinstance(tools, list):
        for index, tool in enumerate(tools):
            description = tool.get("description") if isinstance(tool, dict) else None
            if isinstance(description, str):
                path: list[PathPart] = ["tools", index, "description"]
                _add(extraction, path, description, "tool_definition", True)

    messages = payload.get("messages")
    if not isinstance(messages, list):
        raise PayloadError("request must contain a messages list")
    last_assistant = -1
    for index, message in enumerate(messages):
        if isinstance(message, dict) and message.get("role") == "assistant":
            last_assistant = index
    extraction.current_turn_start = last_assistant + 1

    for index, message in enumerate(messages):
        if not isinstance(message, dict):
            raise PayloadError(f"messages[{index}] must be an object")
        role = message.get("role")
        role = role if isinstance(role, str) else "user"
        content = message.get("content")
        if isinstance(content, str):
            _add(extraction, ["messages", index, "content"], content, role, True)
        else:
            _extract_blocks(content, ["messages", index, "content"], role, True, extraction)


def _extract_blocks(
    blocks: JsonValue,
    prefix: list[PathPart],
    role: str,
    trusted: bool,
    extraction: Extraction,
) -> None:
    if not isinstance(blocks, list):
        return
    for index, block in enumerate(blocks):
        path = [*prefix, index]
        if not isinstance(block, dict):
            continue
        block_type = block.get("type")
        text = block.get("text")
        if block_type in SKIPPED_BLOCKS:
            extraction.notes.append(f"{format_path(path)}: {block_type} block not inspected")
        elif block_type == "text" and isinstance(text, str):
            _add(extraction, [*path, "text"], text, role, trusted)
        elif block_type == "tool_use" or block_type == "server_tool_use":
            name = block.get("name")
            tool_input = block.get("input")
            if isinstance(name, str) and isinstance(tool_input, dict):
                _extract_tool_input(tool_input, [*path, "input"], name, extraction)
        elif block_type == "tool_result":
            content = block.get("content")
            if isinstance(content, str):
                _add(extraction, [*path, "content"], content, "tool", False)
            else:
                _extract_blocks(content, [*path, "content"], "tool", False, extraction)
        elif block_type == "document":
            _extract_document(block, path, role, extraction)
        else:
            # Server tool results, search results and unknown blocks: inspect any prose they
            # carry as untrusted content.
            found = False
            for sub_path, text in _strings(block, path):
                _add(extraction, sub_path, text, "tool", False)
                found = True
            if not found:
                extraction.notes.append(f"{format_path(path)}: {block_type} block has no text")


def _extract_document(
    block: JsonObject, path: list[PathPart], role: str, extraction: Extraction
) -> None:
    source = block.get("source")
    if isinstance(source, dict) and source.get("type") == "text":
        data = source.get("data")
        if isinstance(data, str):
            _add(extraction, [*path, "source", "data"], data, role, False)
            return
    if isinstance(source, dict) and source.get("type") == "content":
        _extract_blocks(
            source.get("content"), [*path, "source", "content"], role, False, extraction
        )
        return
    extraction.notes.append(f"{format_path(path)}: document block not inspected")


def _extract_tool_input(
    tool_input: JsonObject, prefix: list[PathPart], tool_name: str, extraction: Extraction
) -> None:
    for path, text in _strings(tool_input, prefix):
        field_name = next((p for p in reversed(path) if isinstance(p, str)), None)
        extraction.segments.append(
            TextSegment(
                location=format_path(path),
                text=text,
                role="assistant",
                trusted=True,
                tool_name=tool_name,
                tool_field=field_name,
            )
        )


def _strings(value: JsonValue, prefix: list[PathPart]) -> Iterator[tuple[list[PathPart], str]]:
    """Yield (path, text) for every non-empty string leaf, skipping identifier-like keys."""
    if isinstance(value, str):
        if value:
            yield prefix, value
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _strings(item, [*prefix, index])
    elif isinstance(value, dict):
        for key, item in value.items():
            if key not in NON_TEXT_KEYS:
                yield from _strings(item, [*prefix, key])


def _add(extraction: Extraction, path: list[PathPart], text: str, role: str, trusted: bool) -> None:
    if text:
        extraction.segments.append(
            TextSegment(location=format_path(path), text=text, role=role, trusted=trusted)
        )


def _require_str(payload: JsonObject, key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise PayloadError(f"{key} must be a string")
    return value


# --- Redaction --------------------------------------------------------------------


def apply_redactions(payload: JsonObject, findings: Iterable[Finding]) -> JsonObject:
    """Return a copy of `payload` with every redactable finding's span replaced."""
    by_location: dict[str, list[Finding]] = {}
    for finding in findings:
        if finding.location and finding.span and finding.replacement is not None:
            by_location.setdefault(finding.location, []).append(finding)

    redacted = copy.deepcopy(payload)
    for location, items in by_location.items():
        parts = parse_path(location)
        parent = _resolve(redacted, parts[:-1])
        key = parts[-1]
        original = _child(parent, key)
        if not isinstance(original, str):
            raise PayloadError(f"{location} is not a string")
        text = original
        last_start = len(text) + 1
        # Right to left so earlier offsets stay valid; overlapping spans are skipped.
        for finding in sorted(items, key=lambda f: f.span.start if f.span else 0, reverse=True):
            span, replacement = finding.span, finding.replacement
            if span is None or replacement is None or span.end > last_start:
                continue
            text = text[: span.start] + replacement + text[span.end :]
            last_start = span.start
        _set_child(parent, key, text)
    return redacted


def _resolve(root: JsonValue, parts: list[PathPart]) -> JsonValue:
    node = root
    for part in parts:
        node = _child(node, part)
    return node


def _child(node: JsonValue, part: PathPart) -> JsonValue:
    if isinstance(part, int) and isinstance(node, list) and 0 <= part < len(node):
        return node[part]
    if isinstance(part, str) and isinstance(node, dict) and part in node:
        return node[part]
    raise PayloadError(f"path element {part!r} not found")


def _set_child(node: JsonValue, part: PathPart, value: str) -> None:
    if isinstance(part, int) and isinstance(node, list):
        node[part] = value
        return
    if isinstance(part, str) and isinstance(node, dict):
        node[part] = value
        return
    raise PayloadError(f"cannot assign path element {part!r}")

"""SSE streaming support: buffer and audit modes.

- `SSEParser` splits an upstream byte stream into server-sent events, keeping each event's raw
  bytes so unchanged streams can be replayed byte for byte.
- `MessageAccumulator` rebuilds the final Messages API response from stream events, so the
  engine can inspect a streamed response exactly like a non-streamed one.
- `synthesize_events` turns a (redacted or replaced) message back into a valid event sequence.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import cast

from pydantic import JsonValue

from claude_guard.payload import JsonObject

PING_EVENT = b'event: ping\ndata: {"type": "ping"}\n\n'


@dataclass(frozen=True)
class SSEEvent:
    event: str | None
    data: str
    raw: bytes

    def json(self) -> JsonObject | None:
        try:
            parsed = json.loads(self.data)
        except ValueError:
            return None
        return parsed if isinstance(parsed, dict) else None


class SSEParser:
    """Incremental SSE parser. Feed bytes, get complete events."""

    def __init__(self) -> None:
        self._buffer = b""

    def feed(self, chunk: bytes) -> list[SSEEvent]:
        self._buffer += chunk.replace(b"\r\n", b"\n")
        events: list[SSEEvent] = []
        while b"\n\n" in self._buffer:
            raw, self._buffer = self._buffer.split(b"\n\n", 1)
            if raw.strip():
                events.append(_parse_event(raw + b"\n\n"))
        return events

    def flush(self) -> list[SSEEvent]:
        """Return a trailing event that was not terminated by a blank line."""
        raw, self._buffer = self._buffer, b""
        return [_parse_event(raw.rstrip(b"\n") + b"\n\n")] if raw.strip() else []


def _parse_event(raw: bytes) -> SSEEvent:
    event: str | None = None
    data: list[str] = []
    for line in raw.decode("utf-8", errors="replace").split("\n"):
        if line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("data:"):
            data.append(line[5:].removeprefix(" "))
    return SSEEvent(event=event, data="\n".join(data), raw=raw)


def format_event(event: str, data: JsonObject) -> bytes:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n".encode()


@dataclass
class MessageAccumulator:
    """Rebuilds a Messages API response from stream events."""

    message: JsonObject | None = None
    blocks: dict[int, JsonObject] = field(default_factory=dict)
    partial_json: dict[int, str] = field(default_factory=dict)
    error: JsonObject | None = None
    complete: bool = False

    def add(self, event: SSEEvent) -> None:
        data = event.json()
        if data is None:
            return
        kind = data.get("type")
        if kind == "message_start" and isinstance(data.get("message"), dict):
            self.message = dict(cast(JsonObject, data["message"]))
            self.message["content"] = []
        elif kind == "content_block_start":
            index, block = data.get("index"), data.get("content_block")
            if isinstance(index, int) and isinstance(block, dict):
                self.blocks[index] = dict(block)
                if block.get("type") in ("tool_use", "server_tool_use"):
                    self.partial_json[index] = ""
        elif kind == "content_block_delta":
            self._apply_delta(data)
        elif kind == "content_block_stop":
            self._finish_block(data.get("index"))
        elif kind == "message_delta" and self.message is not None:
            delta = data.get("delta")
            if isinstance(delta, dict):
                self.message.update(delta)
            usage = data.get("usage")
            if isinstance(usage, dict):
                merged = dict(cast(JsonObject, self.message.get("usage") or {}))
                merged.update(usage)
                self.message["usage"] = merged
        elif kind == "message_stop":
            self.complete = True
        elif kind == "error":
            error = data.get("error")
            self.error = error if isinstance(error, dict) else {"message": str(error)}

    def result(self) -> JsonObject | None:
        if self.message is None:
            return None
        for index in list(self.partial_json):
            self._finish_block(index)
        message = dict(self.message)
        content: list[JsonValue] = [self.blocks[i] for i in sorted(self.blocks)]
        message["content"] = content
        return message

    def _apply_delta(self, data: JsonObject) -> None:
        index, delta = data.get("index"), data.get("delta")
        if not isinstance(index, int) or not isinstance(delta, dict) or index not in self.blocks:
            return
        block = self.blocks[index]
        kind = delta.get("type")
        if kind == "text_delta":
            block["text"] = _str(block.get("text")) + _str(delta.get("text"))
        elif kind == "input_json_delta":
            self.partial_json[index] = self.partial_json.get(index, "") + _str(
                delta.get("partial_json")
            )
        elif kind == "thinking_delta":
            block["thinking"] = _str(block.get("thinking")) + _str(delta.get("thinking"))
        elif kind == "signature_delta":
            block["signature"] = _str(delta.get("signature"))
        elif kind == "citations_delta":
            citations = block.get("citations")
            items: list[JsonValue] = list(citations) if isinstance(citations, list) else []
            items.append(delta.get("citation"))
            block["citations"] = items

    def _finish_block(self, index: JsonValue) -> None:
        if not isinstance(index, int) or index not in self.partial_json:
            return
        raw = self.partial_json.pop(index)
        try:
            parsed = json.loads(raw) if raw.strip() else {}
        except ValueError:
            parsed = {"_unparsed_input": raw}
        self.blocks[index]["input"] = parsed


def _str(value: JsonValue) -> str:
    return value if isinstance(value, str) else ""


def synthesize_events(message: JsonObject) -> Iterator[bytes]:
    """Yield an SSE event sequence that a client will assemble into `message`."""
    content = message.get("content")
    blocks = content if isinstance(content, list) else []
    usage = message.get("usage")
    usage_obj = usage if isinstance(usage, dict) else {}

    start = {k: v for k, v in message.items() if k not in ("content", "stop_reason")}
    start["content"] = []
    start["stop_reason"] = None
    yield format_event("message_start", {"type": "message_start", "message": start})

    for index, block in enumerate(blocks):
        if not isinstance(block, dict):
            continue
        yield from _synthesize_block(index, block)

    delta: JsonObject = {
        "stop_reason": message.get("stop_reason"),
        "stop_sequence": message.get("stop_sequence"),
    }
    yield format_event(
        "message_delta",
        {
            "type": "message_delta",
            "delta": delta,
            "usage": {"output_tokens": usage_obj.get("output_tokens", 0)},
        },
    )
    yield format_event("message_stop", {"type": "message_stop"})


def _synthesize_block(index: int, block: JsonObject) -> Iterator[bytes]:
    kind = block.get("type")
    if kind == "text":
        start: JsonObject = {"type": "text", "text": ""}
        deltas: list[JsonObject] = [{"type": "text_delta", "text": _str(block.get("text"))}]
    elif kind in ("tool_use", "server_tool_use"):
        start = {k: v for k, v in block.items() if k != "input"}
        start["input"] = {}
        deltas = [
            {
                "type": "input_json_delta",
                "partial_json": json.dumps(block.get("input", {}), ensure_ascii=False),
            }
        ]
    elif kind == "thinking":
        start = {"type": "thinking", "thinking": ""}
        deltas = [{"type": "thinking_delta", "thinking": _str(block.get("thinking"))}]
        if isinstance(block.get("signature"), str):
            deltas.append({"type": "signature_delta", "signature": _str(block.get("signature"))})
    else:
        # Results and redacted thinking arrive complete in content_block_start.
        start, deltas = block, []

    yield format_event(
        "content_block_start",
        {"type": "content_block_start", "index": index, "content_block": start},
    )
    for delta in deltas:
        yield format_event(
            "content_block_delta", {"type": "content_block_delta", "index": index, "delta": delta}
        )
    yield format_event("content_block_stop", {"type": "content_block_stop", "index": index})

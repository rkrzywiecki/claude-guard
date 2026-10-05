"""Helpers to build upstream SSE streams for proxy tests."""

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

import httpx


def event(name: str, data: dict[str, Any]) -> bytes:
    return f"event: {name}\ndata: {json.dumps(data)}\n\n".encode()


def message_start(message_id: str = "msg_1") -> bytes:
    return event(
        "message_start",
        {
            "type": "message_start",
            "message": {
                "id": message_id,
                "type": "message",
                "role": "assistant",
                "model": "claude-opus-5-5",
                "content": [],
                "stop_reason": None,
                "stop_sequence": None,
                "usage": {"input_tokens": 12, "output_tokens": 1},
            },
        },
    )


def text_stream(*parts: str) -> list[bytes]:
    events = [
        message_start(),
        event(
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            },
        ),
        event("ping", {"type": "ping"}),
    ]
    events += [
        event(
            "content_block_delta",
            {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": p}},
        )
        for p in parts
    ]
    events += [
        event("content_block_stop", {"type": "content_block_stop", "index": 0}),
        event(
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                "usage": {"output_tokens": 20},
            },
        ),
        event("message_stop", {"type": "message_stop"}),
    ]
    return events


def tool_use_stream(name: str, input_json: str, chunk: int = 7) -> list[bytes]:
    pieces = [input_json[i : i + chunk] for i in range(0, len(input_json), chunk)]
    return [
        message_start(),
        event(
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "tool_use", "id": "toolu_1", "name": name, "input": {}},
            },
        ),
        *[
            event(
                "content_block_delta",
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "input_json_delta", "partial_json": piece},
                },
            )
            for piece in pieces
        ],
        event("content_block_stop", {"type": "content_block_stop", "index": 0}),
        event(
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": "tool_use", "stop_sequence": None},
                "usage": {"output_tokens": 30},
            },
        ),
        event("message_stop", {"type": "message_stop"}),
    ]


class ChunkedStream(httpx.AsyncByteStream):
    """An upstream body delivered in chunks, optionally slowly or failing midway."""

    def __init__(
        self, chunks: list[bytes], delay: float = 0.0, fail_after: int | None = None
    ) -> None:
        self.chunks = chunks
        self.delay = delay
        self.fail_after = fail_after

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for index, chunk in enumerate(self.chunks):
            if self.fail_after is not None and index == self.fail_after:
                raise httpx.ReadError("connection reset")
            if self.delay:
                await asyncio.sleep(self.delay)
            yield chunk


def sse_response(
    chunks: list[bytes], delay: float = 0.0, fail_after: int | None = None
) -> httpx.Response:
    return httpx.Response(
        200,
        headers={"content-type": "text/event-stream", "request-id": "req_stream"},
        stream=ChunkedStream(chunks, delay, fail_after),
    )

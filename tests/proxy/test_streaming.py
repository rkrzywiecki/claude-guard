"""Tests for SSE parsing, message accumulation and event synthesis."""

import json

from claude_guard.payload import JsonObject
from claude_guard.proxy.streaming import (
    MessageAccumulator,
    SSEParser,
    synthesize_events,
)
from tests.proxy.sse import event, text_stream, tool_use_stream


def accumulate(chunks: list[bytes]) -> MessageAccumulator:
    parser = SSEParser()
    accumulator = MessageAccumulator()
    for chunk in chunks:
        for item in parser.feed(chunk):
            accumulator.add(item)
    for item in parser.flush():
        accumulator.add(item)
    return accumulator


def test_parser_handles_split_chunks_and_crlf() -> None:
    raw = b"".join(text_stream("Hello", " world")).replace(b"\n", b"\r\n")
    parser = SSEParser()
    events = []
    for i in range(0, len(raw), 5):
        events += parser.feed(raw[i : i + 5])
    names = [e.event for e in events]
    assert names[0] == "message_start"
    assert names[-1] == "message_stop"
    assert events[0].raw.endswith(b"\n\n")


def test_parser_flushes_unterminated_event() -> None:
    parser = SSEParser()
    assert parser.feed(b'event: ping\ndata: {"type": "ping"}') == []
    [item] = parser.flush()
    assert item.event == "ping"
    assert item.json() == {"type": "ping"}


def test_parser_multiline_data() -> None:
    [item] = SSEParser().feed(b"event: x\ndata: a\ndata: b\n\n")
    assert item.data == "a\nb"
    assert item.json() is None


def test_accumulates_text_message() -> None:
    accumulator = accumulate(text_stream("Hel", "lo", "!"))
    message = accumulator.result()
    assert message is not None
    assert accumulator.complete
    assert message["content"] == [{"type": "text", "text": "Hello!"}]
    assert message["stop_reason"] == "end_turn"
    assert message["usage"] == {"input_tokens": 12, "output_tokens": 20}


def test_accumulates_tool_use_input_from_partial_json() -> None:
    message = accumulate(tool_use_stream("Bash", '{"command": "rm -rf /"}')).result()
    assert message is not None
    assert message["content"] == [
        {"type": "tool_use", "id": "toolu_1", "name": "Bash", "input": {"command": "rm -rf /"}}
    ]


def test_unparsable_tool_input_is_kept_for_inspection() -> None:
    chunks = tool_use_stream("Bash", '{"command": "rm -rf /"}')
    message = accumulate(chunks[:4]).result()  # stream cut in the middle of the JSON
    assert message is not None
    assert message["content"] == [
        {
            "type": "tool_use",
            "id": "toolu_1",
            "name": "Bash",
            "input": {"_unparsed_input": '{"command": "r'},
        }
    ]


def test_accumulates_thinking_and_error() -> None:
    chunks = [
        text_stream("x")[0],
        event(
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "thinking", "thinking": ""},
            },
        ),
        event(
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "thinking_delta", "thinking": "hmm"},
            },
        ),
        event(
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "signature_delta", "signature": "sig"},
            },
        ),
        event("error", {"type": "error", "error": {"type": "overloaded_error", "message": "busy"}}),
    ]
    accumulator = accumulate(chunks)
    message = accumulator.result()
    assert message is not None
    assert message["content"] == [{"type": "thinking", "thinking": "hmm", "signature": "sig"}]
    assert accumulator.error == {"type": "overloaded_error", "message": "busy"}
    assert not accumulator.complete


def test_no_message_without_message_start() -> None:
    assert accumulate([event("ping", {"type": "ping"})]).result() is None


def test_synthesized_events_round_trip() -> None:
    original: JsonObject = {
        "id": "msg_9",
        "type": "message",
        "role": "assistant",
        "model": "m",
        "content": [
            {"type": "thinking", "thinking": "plan", "signature": "s"},
            {"type": "text", "text": "Running it."},
            {"type": "tool_use", "id": "toolu_2", "name": "Bash", "input": {"command": "ls"}},
            {"type": "web_search_tool_result", "tool_use_id": "s1", "content": []},
        ],
        "stop_reason": "tool_use",
        "stop_sequence": None,
        "usage": {"input_tokens": 3, "output_tokens": 9},
    }
    chunks = list(synthesize_events(original))
    accumulator = accumulate(chunks)
    assert accumulator.complete
    assert accumulator.result() == original
    first = json.loads(chunks[0].split(b"data: ", 1)[1])
    assert first["message"]["content"] == []
    assert first["message"]["stop_reason"] is None

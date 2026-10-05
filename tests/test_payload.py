"""Tests for payload extraction, paths and redaction."""

import pytest

from claude_guard.models import (
    Action,
    Category,
    Direction,
    Finding,
    Severity,
    Span,
)
from claude_guard.payload import (
    JsonObject,
    PayloadError,
    apply_redactions,
    extract,
    format_path,
    parse_path,
)
from tests.fixtures import load


def redact_finding(location: str, start: int, end: int, replacement: str = "[R]") -> Finding:
    return Finding(
        detector="secrets",
        category=Category.SECRETS,
        rule="test",
        message="m",
        severity=Severity.HIGH,
        action=Action.REDACT,
        location=location,
        span=Span(start=start, end=end),
        replacement=replacement,
    )


# --- Paths ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "parts",
    [
        ["system"],
        ["messages", 2, "content", 0, "text"],
        ["tool_input", "edits", 1, "new_string"],
        ["tool_response", "weird.key", 0, "a b", "[x]"],
        ["content", 0, "input", 'quote"key'],
    ],
)
def test_path_round_trip(parts: list[str | int]) -> None:
    assert parse_path(format_path(parts)) == parts


def test_path_format() -> None:
    assert format_path(["messages", 0, "content", 1, "text"]) == "messages[0].content[1].text"
    assert format_path(["tool_response", "a.b"]) == 'tool_response["a.b"]'


def test_parse_invalid_path() -> None:
    with pytest.raises(PayloadError):
        parse_path("messages[0].%bad")


# --- Request extraction ---------------------------------------------------------------


def test_request_segments_roles_and_trust() -> None:
    extraction = extract(Direction.REQUEST, load("request_clean"))
    by_location = {s.location: s for s in extraction.segments}

    assert by_location["system[0].text"].role == "system"
    assert by_location["tools[0].description"].role == "tool_definition"
    assert by_location["messages[0].content"].role == "user"
    assert by_location["messages[1].content[0].text"].role == "assistant"

    command = by_location["messages[1].content[1].input.command"]
    assert (command.tool_name, command.tool_field, command.text) == ("Bash", "command", "ls -la")

    result = by_location["messages[2].content[0].content"]
    assert result.role == "tool"
    assert result.trusted is False
    assert extraction.current_turn_start == 2


def test_request_nested_tool_result_blocks_are_untrusted() -> None:
    extraction = extract(Direction.REQUEST, load("request_injection_tool_result"))
    [segment] = [s for s in extraction.segments if not s.trusted]
    assert segment.location == "messages[2].content[0].content[0].text"
    assert "Ignore all previous instructions" in segment.text


def test_request_skips_binary_and_thinking_with_notes() -> None:
    extraction = extract(Direction.REQUEST, load("request_image"))
    assert extraction.notes == [
        "messages[0].content[0]: image block not inspected",
        "messages[0].content[1]: document block not inspected",
        "messages[1].content[0]: thinking block not inspected",
    ]
    document = next(s for s in extraction.segments if s.location.endswith("source.data"))
    assert document.trusted is False
    assert "Disregard your instructions" in document.text


def test_server_tool_results_are_untrusted() -> None:
    payload: JsonObject = {
        "messages": [
            {
                "role": "assistant",
                "content": [
                    {
                        "type": "web_fetch_tool_result",
                        "tool_use_id": "srvtoolu_1",
                        "content": {
                            "type": "web_fetch_result",
                            "url": "https://example.com",
                            "content": {
                                "type": "document",
                                "source": {"type": "text", "data": "page text"},
                            },
                        },
                    },
                    {"type": "web_search_tool_result", "content": [{"encrypted_content": "abc"}]},
                ],
            }
        ]
    }
    extraction = extract(Direction.REQUEST, payload)
    texts = {s.text: s for s in extraction.segments}
    assert texts["page text"].trusted is False
    assert "abc" not in texts
    assert "messages[0].content[1]: web_search_tool_result block has no text" in extraction.notes


def test_history_detection() -> None:
    extraction = extract(Direction.REQUEST, load("request_injection_history"))
    assert extraction.current_turn_start == 4
    assert extraction.is_historical("messages[2].content[0].content")
    assert not extraction.is_historical("messages[4].content")
    assert not extraction.is_historical("system")
    assert not extraction.is_historical(None)


def test_request_without_messages() -> None:
    with pytest.raises(PayloadError, match="messages"):
        extract(Direction.REQUEST, {"model": "x"})


# --- Other directions -------------------------------------------------------------


def test_response_extraction() -> None:
    extraction = extract(Direction.RESPONSE, load("response_rm_rf"))
    locations = {s.location: s for s in extraction.segments}
    assert locations["content[0].text"].role == "assistant"
    command = locations["content[1].input.command"]
    assert command.tool_name == "Bash"
    assert command.tool_field == "command"


def test_tool_input_extraction() -> None:
    extraction = extract(Direction.TOOL_INPUT, load("tool_input_edit"))
    fields = {s.tool_field: s for s in extraction.segments}
    assert set(fields) == {"file_path", "old_string", "new_string"}
    assert fields["file_path"].location == "tool_input.file_path"
    assert all(s.tool_name == "Edit" for s in extraction.segments)


def test_tool_input_nested_field_names() -> None:
    payload: JsonObject = {
        "tool_name": "MultiEdit",
        "tool_input": {"file_path": "a.py", "edits": [{"old_string": "x", "new_string": "y"}]},
    }
    extraction = extract(Direction.TOOL_INPUT, payload)
    nested = next(s for s in extraction.segments if s.text == "y")
    assert nested.location == "tool_input.edits[0].new_string"
    assert nested.tool_field == "new_string"


def test_tool_output_is_untrusted_and_not_a_tool_call() -> None:
    extraction = extract(Direction.TOOL_OUTPUT, load("tool_output_injection"))
    [segment] = extraction.segments
    assert segment.location == "tool_response.result"
    assert segment.trusted is False
    assert segment.tool_name is None


@pytest.mark.parametrize(
    ("direction", "payload", "message"),
    [
        (Direction.TOOL_INPUT, {"tool_input": {}}, "tool_name"),
        (Direction.TOOL_INPUT, {"tool_name": "Bash", "tool_input": "ls"}, "tool_input"),
        (Direction.TOOL_OUTPUT, {"tool_response": "x"}, "tool_name"),
    ],
)
def test_invalid_hook_payloads(
    direction: Direction, payload: dict[str, object], message: str
) -> None:
    with pytest.raises(PayloadError, match=message):
        extract(direction, payload)  # type: ignore[arg-type]


# --- Redaction --------------------------------------------------------------------


def test_redaction_replaces_multiple_spans_right_to_left() -> None:
    payload: JsonObject = {"messages": [{"role": "user", "content": "key AAAA and BBBB end"}]}
    redacted = apply_redactions(
        payload,
        [
            redact_finding("messages[0].content", 4, 8, "[K1]"),
            redact_finding("messages[0].content", 13, 17, "[K2]"),
        ],
    )
    assert redacted["messages"] == [{"role": "user", "content": "key [K1] and [K2] end"}]
    assert payload["messages"] == [{"role": "user", "content": "key AAAA and BBBB end"}]


def test_redaction_in_nested_block() -> None:
    payload = load("response_secret")
    text = payload["content"][0]["text"]  # type: ignore[index,call-overload]
    assert isinstance(text, str)
    start = text.index("ghp_")
    redacted = apply_redactions(payload, [redact_finding("content[0].text", start, start + 40)])
    assert "ghp_" not in str(redacted)
    assert "[R]" in str(redacted)


def test_redaction_skips_overlapping_spans() -> None:
    payload: JsonObject = {"system": "0123456789"}
    redacted = apply_redactions(
        payload, [redact_finding("system", 2, 6, "[A]"), redact_finding("system", 4, 8, "[B]")]
    )
    assert redacted == {"system": "0123[B]89"}


def test_redaction_ignores_findings_without_span() -> None:
    finding = redact_finding("system", 0, 1).model_copy(update={"span": None})
    assert apply_redactions({"system": "abc"}, [finding]) == {"system": "abc"}


def test_redaction_unknown_location() -> None:
    with pytest.raises(PayloadError):
        apply_redactions({"system": "abc"}, [redact_finding("messages[3].content", 0, 1)])

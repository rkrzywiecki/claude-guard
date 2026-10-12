"""Tests for the per-tool policy (deny, allow and warn lists)."""

from pathlib import Path
from typing import Any

import pytest

from claude_guard.config import Policy, PolicyError, Settings, ToolsPolicy, load_policy
from claude_guard.detectors.tools import ToolPolicyDetector
from claude_guard.engine import GuardEngine
from claude_guard.models import Action, Category, Direction, InspectionContext, ToolCall


def detector(**tools: Any) -> ToolPolicyDetector:
    return ToolPolicyDetector(Policy(tools=ToolsPolicy(**tools)))


def calls(*names: str, direction: Direction = Direction.TOOL_INPUT) -> InspectionContext:
    return InspectionContext(
        direction=direction,
        tool_calls=tuple(
            ToolCall(name=name, location=f"content[{i}]") for i, name in enumerate(names)
        ),
    )


async def outcome(det: ToolPolicyDetector, ctx: InspectionContext) -> list[tuple[str, Action]]:
    return [(f.rule, f.action) for f in await det.detect(ctx)]


# --- Lists ----------------------------------------------------------------------------


async def test_default_policy_allows_everything() -> None:
    assert await outcome(detector(), calls("Bash", "mcp__x__y", "WebFetch")) == []


async def test_deny_globs() -> None:
    det = detector(deny=["mcp__untrusted__*", "WebFetch"])
    assert await outcome(det, calls("mcp__untrusted__read", "WebFetch", "Bash")) == [
        ("tool_denied", Action.BLOCK),
        ("tool_denied", Action.BLOCK),
    ]


async def test_allow_list_denies_everything_else() -> None:
    det = detector(allow=["Read", "Grep", "mcp__github__*"])
    assert await outcome(
        det, calls("Read", "mcp__github__list_prs", "Bash", "mcp__slack__post")
    ) == [
        ("tool_not_allowed", Action.BLOCK),
        ("tool_not_allowed", Action.BLOCK),
    ]


async def test_deny_wins_over_allow() -> None:
    det = detector(allow=["mcp__github__*"], deny=["mcp__github__delete_*"])
    assert await outcome(det, calls("mcp__github__delete_repo")) == [("tool_denied", Action.BLOCK)]


async def test_warn_list_only_warns() -> None:
    det = detector(warn=["mcp__*"])
    [finding] = await det.detect(calls("mcp__fs__write"))
    assert (finding.rule, finding.action, finding.category) == (
        "tool_watched",
        Action.WARN,
        Category.TOOLS,
    )
    assert finding.excerpt == "mcp__fs__write"
    assert finding.location == "content[0]"


async def test_globs_are_case_sensitive() -> None:
    assert await outcome(detector(deny=["bash"]), calls("Bash")) == []


async def test_policy_action_and_disable() -> None:
    assert await outcome(detector(deny=["Bash"], action="warn"), calls("Bash")) == [
        ("tool_denied", Action.WARN)
    ]
    assert await outcome(detector(deny=["Bash"], enabled=False), calls("Bash")) == []


async def test_direction_override() -> None:
    det = detector(deny=["Bash"], direction_actions={"response": "warn"})
    assert await outcome(det, calls("Bash", direction=Direction.RESPONSE)) == [
        ("tool_denied", Action.WARN)
    ]


async def test_request_history_not_checked() -> None:
    assert await outcome(detector(deny=["Bash"]), calls("Bash", direction=Direction.REQUEST)) == []


def test_empty_glob_rejected(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text("tools:\n  deny: ['']\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="must not be empty"):
        load_policy(path)


def test_redact_action_rejected(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text("tools:\n  action: redact\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="redact"):
        load_policy(path)


# --- Through the engine ---------------------------------------------------------------


@pytest.fixture
def engine(tmp_path: Path) -> GuardEngine:
    policy = Policy(tools=ToolsPolicy(deny=["mcp__untrusted__*"]))
    return GuardEngine(policy, Settings(audit_path=tmp_path / "audit.jsonl"))


async def test_tool_call_without_arguments_is_checked(engine: GuardEngine) -> None:
    verdict = await engine.inspect(
        Direction.TOOL_INPUT, {"tool_name": "mcp__untrusted__list", "tool_input": {}}
    )
    assert verdict.action is Action.BLOCK
    assert [f.rule for f in verdict.findings] == ["tool_denied"]


async def test_tool_use_in_response_is_checked(engine: GuardEngine) -> None:
    response = {
        "role": "assistant",
        "content": [
            {"type": "text", "text": "Let me look."},
            {"type": "tool_use", "id": "t1", "name": "mcp__untrusted__read", "input": {}},
        ],
    }
    verdict = await engine.inspect(Direction.RESPONSE, response)
    assert verdict.action is Action.BLOCK
    [finding] = verdict.findings
    assert finding.location == "content[1]"
